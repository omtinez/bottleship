# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import time
import uuid
import hmac
import base64
import hashlib
import inspect
import argparse

import bottle
from pddb import PandasDatabase


# Python 2.x vs 3.x compatibility
def tob(s, enc='utf8'):
    if sys.version_info >= (3, 0, 0) and isinstance(s, str):
        s = s.encode(enc)
    elif sys.version_info < (3, 0, 0) and isinstance(s, unicode):
        s = s.encode(enc)
    return s
def tos(s, enc='utf8'):
    if sys.version_info >= (3, 0, 0) and isinstance(s, bytes):
        s = s.decode(enc)
    elif sys.version_info < (3, 0, 0) and isinstance(s, unicode):
        s = s.encode(enc)
    return s

def _lscmp(a, b):
    ''' Compares two strings in a cryptographically safe way:
        Runtime is not affected by length of common prefix. '''
    return not sum(0 if x==y else 1 for x, y in zip(a, b)) and len(a) == len(b)

def data_encode(data, key, digestmod=None):
    ''' Encode and sign a pickle-able object. Return a (byte) string '''
    digestmod = digestmod or hashlib.sha256
    data, key = base64.b64encode(tob(data)), tob(key)
    sig = base64.b64encode(hmac.new(key, data, digestmod=digestmod).digest())
    return tob('!') + sig + tob('?') + data

def data_decode(data, key, digestmod=None):
    ''' Verify and decode an encoded string. Return an object or None.'''
    digestmod = digestmod or hashlib.sha256
    data, key = tob(data), tob(key)
    if data_is_encoded(data):
        sig, data = data.split(tob('?'), 1)
        if _lscmp(sig[1:], base64.b64encode(hmac.new(key, data, digestmod=digestmod).digest())):
            return tos(base64.b64decode(data))
    return None

def data_is_encoded(data):
    ''' Return True if the argument looks like a encoded cookie.'''
    datab = tob(data)
    return bool(datab.startswith(tob('!')) and tob('?') in datab)

class BottleShip(bottle.Bottle):
    '''
    Subclass of bottle.Bottle.

    Each instance of this class corresponds to a single, distinct web application. See
    documentation on bottle.Bottle for additional information about this class and its methods.

    Options
    -------
    pddb : PandasDatabase
        Use the given PandasDatabase object instead of instantiating a new one.
    whitelist_cond : dict
        Conditions to match a new user against. When provided, each item in this dictionary will
        be compared for equality against the `user_info` dictionary passed as an argument to the
        `BottleShip.register()` function.
    blacklist_cond : dict
        Conditions to avoid matching a new user against. When provided, each item in the
        `user_info` dictionary passed as an argument to the `BottleShip.register()` function will
        be compared for inequality against this dictionary.
    allowed_security : array-like (default `["plaintext", "plaintext+ipaddr", "hmac", "hmac+ipaddr"]`)
        Type of security allowed for user authentication. Possible values are:
        ["plaintext", "plaintext+ipaddr", "hmac", "hmac+ipaddr"]
    token_lifetime_seconds : int (default `3600`)
        Number of seconds after which a user token expires.
    max_tokens_per_user : int (default `5`)
        Maximum number of tokens allowed per user. After the limit is reached, new token
        associations will trigger immediate expiration of the oldest token assigned to the user.
    catchall : boolean (default `True`)
        See bottle.Bottle for more information.
    autojson : boolean (default `True`)
        See bottle.Bottle for more information.
    debug : boolean (default `True`)
        When true, prints information about internal operations to the console.
    '''

    def __init__(self, pddb=None, whitelist_cond=None, blacklist_cond=None, allowed_security=None,
                 token_lifetime_seconds=3600, max_tokens_per_user=5, catchall=True, autojson=True,
                 debug=False):

        super(BottleShip, self).__init__()
        self.pddb = pddb or PandasDatabase('bottleship_db', debug=debug)
        self.allowed_security = allowed_security or ('plaintext', 'plaintext+ipaddr', 'hmac', 'hmac+ipaddr')

        table_names = ('bottleship_users', 'bottleship_tokens')
        self.pddb.load(table_names)

        self._rsakey_public = None
        self._rsakey_private = None
        self._key_store = dict()
        self._token_lifetime_seconds = token_lifetime_seconds
        self._whitelist_cond = whitelist_cond or dict()
        self._blacklist_cond = blacklist_cond or dict()
        self._debug = debug

        # If rsa is allowed, generate key pair now
        if any(['rsa' in sec for sec in self.allowed_security]):
            
            # Only import the cryptography module if necessary to avoid it as a dependency
            try:
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
            except ImportError:
                self._print('RSA is not supported in this system because the cryptography module '
                            'is not installed. To install it, you can run `$ pip install '
                            'cryptography`. RSA encryption has been disabled for this instance.')
                self.allowed_security = [sec for sec in self.allowed_security if 'rsa' not in sec]
            
            self._rsakey_private = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend())    
            self._rsakey_public = self._rsakey_private.public_key()        
            
    def _print(self, txt):
        if self._debug:
            print(txt)

    def _check_user(self, user_record):
        ''' Test the user record against our whitelist and blacklist '''
        cond_keys = set(list(self._blacklist_cond.keys()) + list(self._whitelist_cond.keys()))

        for cond in cond_keys:
            #self.pddb._regex_type TODO

            if cond in self._whitelist_cond:
                whitelist_cond = self._whitelist_cond[cond]
                if not isinstance(whitelist_cond, (list, tuple)):
                    whitelist_cond = (whitelist_cond,)
                if any([user_record.get(cond) != wc for wc in whitelist_cond]):
                    return False

            if cond in self._blacklist_cond:
                blacklist_cond = self._blacklist_cond[cond]
                if not isinstance(blacklist_cond, (list, tuple)):
                    blacklist_cond = (blacklist_cond,)
                if any([user_record.get(cond) == bc for bc in blacklist_cond]):
                    return False

        return True

    def _gen_token(self, username, security_level=None, key=None):
        ''' Generates a new token for a username and stores it in the database '''

        # Generate the appropriate token for the given security level
        security_level = security_level or self.allowed_security[0]
        if security_level in ('plaintext', 'plaintext+ipaddr', 'hmac', 'hmac+ipaddr'):
            token = str(uuid.uuid4()) # TODO
        else:
            raise NotImplementedError(
                'Token could not be generated for requested security level')

        # Set expiration time, username, etc.
        token_record = {
            'Token': token,
            'Expiry': str(time.time() + self._token_lifetime_seconds),
            'Username': username,
            'SecurityLevel': security_level,
            'Key': key or '',
        }
        print(token_record)
        token_record = self.pddb.insert('bottleship_tokens', record=token_record, astype='dict')
        return token_record

    def _dump_user_record(self, security_level, user_record):
        user_record_json = json.dumps(user_record)
        if 'hmac' in security_level:
            user_record_json = data_encode(user_record_json, user_record.get('Key'))
        elif 'rsa' in security_level:
            user_publickey = load_pem_public_key(
                user_record.get('Key'), backend=default_backend())
            if not isinstance(user_publickey, rsa.RSAPublicKey):
                msg = 'Login error: User key could not be loaded as RSA public key.'
                self._print(msg)
                return bottle.HTTPResponse(status=403, body=msg)
            user_record_json = user_publickey.encrypt(
                user_record_json, padding.OAEP(mgf=padding.MGF1(
                    algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
        return user_record_json

    def _read_secure_json(self, data):
        '''
        Read secure JSON data in the format {"Data": <secure_json>, "Token": <single-use token>}.
        Returns <data_dict, error_message>
        '''

        err_msg = None
        if data.get('Token') not in self._key_store:
            err_msg = ('Security error: Single-use token could not be found in the key store. '
                       'Please request a new one using the key exchange API.')
            return None, err_msg

        # Retrieve and delete single-use token
        security_level, user_key, server_key = self._key_store.pop(data.get('Token'))

        data_json = None
        if 'hmac' in security_level:
            if data_is_encoded(data.get('Data')):
                data_json = data_decode(data.get('Data'), server_key)
            else:
                err_msg = ('Security error: Provided data was not encoded but the security level '
                           'requires it.')
                return None, err_msg
        elif 'rsa' in security_level:
            data_json = self._rsakey_private.decrypt(data.get('Data'), padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(), label=None))
        else:
            err_msg = ('Security error: Provided security level is not supported. Must be one of: '
                        '%r.' % [sec for sec in self.allowed_security if 'hmac' in sec or 'rsa' in sec])
            return None, err_msg

        # Attempt to parse the data into a dictionary and return it
        data_dict = None
        try:
            data_dict = json.loads(tob(data_json).decode('unicode_escape').strip('"'))
            data_dict['Key'] = user_key
        except TypeError:
            err_msg = ('Security error: Provided data was corrupted and could not be parsed as a '
                        'JSON object.')
            return None, err_msg

        return data_dict, err_msg

    def _error_username_password(self, username, password):
        ''' Returns error message if verification fails, None otherwise '''

        # Make sure that username is not empty
        if not username:
            return 'Username error: Parameter "username" cannot be empty.'

        # Make sure that username and password are of the correct type
        if not isinstance(username, str) or not isinstance(password, str):
            return 'Credential error: Parameters "username" and "password" must be of type "str".'

    def key_exchange(self, security_level, user_key):
        '''
        Exchange keys with client.

        Parameters
        ----------
        security_level : str
            Security level will determine the type of encryption/signing to be performed on the
            data as well as the type of keys being exchanged. Must be either ``hmac`` or ``rsa``.
        user_key : str
            String representation of the key from the client. If ``hmac`` this will be the secret
            key used to sign data between client and server; if ``rsa`` this will be the client\'s
            public key.

        Returns
        -------
        response : bottle.HTTPResponse
            Status code and body will determine if the key exchange was successful. If successful,
            the body will contain the single-use token that the client must present along with the
            encoded data. If the security level is ``rsa``, it will also contain the server\'s
            public key.

        Examples
        --------
        >>> app = BottleShip()
        >>> res = app.key_exchange('hmac', '5f04ee43-83bb-46c0-96aa-65a2c5').body
        >>> res
            b'!RWEEi79yWn5BEcse1bmDBBswlcIY2P817ibkZ4UY/kU=?eyJUb2tlbiI6ICI3YTNmMWRlYS0zOGE1LTQ2ODA
            tOTU0Zi1iMjA1OTQwMmVlZGUifQ=='
        >>> bottleship.data_decode(res, '5f04ee43-83bb-46c0-96aa-65a2c5')
            '{"Token": "ce045d43-4e42-4531-9370-8928598b6e26"}'
        '''
        token_json = None
        server_key = None
        user_uuid = str(uuid.uuid4())
        if 'hmac' in security_level and security_level in self.allowed_security:
            server_key = user_key
            token_json = json.dumps({'Token': user_uuid})
            token_json = data_encode(token_json, user_key)
        elif 'rsa' in security_level and security_level in self.allowed_security:
            server_key = self._rsakey_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            token_json = json.dumps({'Token': user_uuid, 'Key': server_key})
            user_publickey = load_pem_public_key(user_key, backend=default_backend())
            if not isinstance(user_publickey, rsa.RSAPublicKey):
                msg = 'Key exchange error: User key could not be loaded as RSA public key.'
                self._print(msg)
                return bottle.HTTPResponse(status=403, body=msg)
            token_json = user_publickey.encrypt(
                token_json, padding.OAEP(mgf=padding.MGF1(
                    algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
        else:
            msg = ('Key exchange error: Requested security level not supported. It must be one of: '
                   '%r' % [sec for sec in self.allowed_security if 'hmac' in sec or 'rsa' in sec])
            self._print(msg)
            res = bottle.HTTPResponse(status=400, body=msg)
            return res

        self._key_store[user_uuid] = (security_level, user_key, server_key)
        return bottle.HTTPResponse(status=200, body=token_json)

    def register(self, username=None, password=None, user_info=None):
        '''
        Register a new user.

        Parameters
        ----------
        username : str
            Username to register. Must be unique in the application. It can also be passed as the
            value of key `Username` as part of the GET or POST request.
        password : str
            Plaintext password for this username. It can also be passed as the value of key
            `Password` as part of the GET or POST request.
        user_info : dict
            Dictionary containing any additional information about this user. The key
            `RemoteIpAddr` will be added to this dictionary with the value provided by
            `bottle.request.environ.get("REMOTE_ADDR")` prior to matching the user against the
            whitelist and blacklist parameters given to the constructor of this class.
            The parameters `username` and `password` can also be passed to this method as items in
            the `user_info` dictionary. Any key-value pairs not described above that are passed as
            part of the GET or POST request will be added to this dictionary. If the requested
            security level requires it, all user info including username and password must be
            serialized and signed/encrypted into a field named `Data` as a json string. In that
            case, the single-use `Token` provided by the key exchange must also be provided.

        Returns
        -------
        response : bottle.HTTPResponse
            Status code and body will determine if the login was successful. If successful, the
            body will contain the user record in JSON format. 

        Examples
        --------
        >>> app = BottleShip()
        >>> app.register("john", "1234").body
            '{"Username": "john", "Password": "4900477947375830305", "__id__": "2c849965-251f-4b5d-
            8a27-77f86fa9e0e3", "RemoteIpAddr": null}'
        '''
        request_dict = PandasDatabase._request(bottle.request, request_fallback=user_info)

        # If data and token are provided, then this must be secure data transfer
        secure_data = False
        if 'Data' in request_dict and 'Token' in request_dict:
            secure_data = True
            request_dict, err_msg = self._read_secure_json(request_dict)
            if err_msg:
                self._print(err_msg)
                return bottle.HTTPResponse(status=400, body=err_msg)

        # Cleanup information from the request
        request_dict = {tos(req_k): tos(req_v) for req_k, req_v in request_dict.items()
                        if re.match(PandasDatabase._colname_rgx, tos(req_k))}

        # Verify username and password
        username = username or request_dict.get('Username')
        password = password or request_dict.get('Password', '')
        auth_header = bottle.request.get_header('Authorization')
        if auth_header: # If auth is available in the headers, take that
            username, password = bottle.parse_auth(auth_header)
        error_msg = self._error_username_password(username, password)
        if error_msg:
            self._print(error_msg)
            return bottle.HTTPResponse(status=400, body=error_msg)

        # Look for existing user record and, if any, reject registration
        user_record = self.pddb.find_one(
            'bottleship_users', where={'Username': username}, astype='dict')
        if user_record:
            msg = 'Register error: Provided username already exists in the database.'
            self._print(msg)
            return bottle.HTTPResponse(status=400, body=msg)

        # Get the user requested security level or default
        security_level = request_dict.get('SecurityLevel', self.allowed_security[0])
        request_dict['SecurityLevel'] = security_level
        if security_level not in self.allowed_security:
            msg = 'Login error: Security level must be one of: %r' % list(self.allowed_security)
            self._print(msg)
            res = bottle.HTTPResponse(status=400, body=msg)
            return res
        elif not secure_data and ('hmac' in security_level or 'rsa' in security_level):
            msg = ('Login error: Security level requested requires secure data transfer but '
                   'plaintext was used instead')
            self._print(msg)
            res = bottle.HTTPResponse(status=400, body=msg)
            return res

        # Get user's IP address from request
        request_dict['RemoteIpAddr'] = bottle.request.environ.get('REMOTE_ADDR', '')

        # Insert the hashed password into user's record
        if password is not None:
            request_dict['Password'] = str(hash(password))

        # Validate the user against our rules
        if not self._check_user(request_dict):
            msg = 'User does not meet the requirements.'
            self._print(msg)
            return bottle.HTTPResponse(status=403, body=msg)

        # Insert or update the user record
        user_cond = {'Username': username}
        user_record = self.pddb.upsert('bottleship_users', record=request_dict, 
                                       where=user_cond, astype='dict')[0]

        # Depending on the security level, we may need to encrypt or sign the data
        user_record_json = self._dump_user_record(security_level, user_record)

        # Return the inserted user record
        return bottle.HTTPResponse(status=200, body=user_record_json)

    def login(self, username=None, password=None, _request_fallback=None):
        '''
        Log in an existing user.

        Parameters
        ----------
        username : str
            Username to login. It can also be passed as the value of key `Username` as part of the
            GET or POST request.
        password : str
            Plaintext password for this username. It can also be passed as the value of key
            `Password` as part of the GET or POST request. If the requested security level requires
            it, password must be signed/encrypted.
        _request_fallback : dict
            Used for testing purposes.
            The parameters `Username` and `Password` can also be passed to this method as items in
            the `_request_fallback` dictionary.

        Returns
        -------
        response : bottle.HTTPResponse
            Status code and body will determine if the login was successful. If successful, the
            body will contain the user record in JSON format. 

        Examples
        --------
        >>> app = BottleShip()
        >>> res = app.login("john", "1234")
        >>> print(res.status_code, res.body)
            403 Login error: Provided password does not match records for that username or username does not exist.
        '''
        request_dict = PandasDatabase._request(bottle.request, request_fallback=_request_fallback)

        # If data and token are provided, then this must be secure data transfer
        secure_data = False
        if 'Data' in request_dict and 'Token' in request_dict:
            secure_data = True
            request_dict, err_msg = self._read_secure_json(request_dict)
            if err_msg:
                self._print(err_msg)
                return bottle.HTTPResponse(status=400, body=err_msg)

        # Cleanup information from the request
        request_dict = {tos(req_k): tos(req_v) for req_k, req_v in request_dict.items()
                        if re.match(PandasDatabase._colname_rgx, tos(req_k))}

        # Verify username and password
        username = username or request_dict.get('Username')
        password = password or request_dict.get('Password', '')
        auth_header = bottle.request.get_header('Authorization')
        if auth_header: # If auth is available in the headers, take that
            username, password = bottle.parse_auth(auth_header)
        error_msg = self._error_username_password(username, password)
        if error_msg:
            self._print(error_msg)
            return bottle.HTTPResponse(status=400, body=error_msg)

        # Look for existing user record
        user_record = self.pddb.find_one(
            'bottleship_users', where={'Username': username}, astype='dict')
        if not user_record:
            msg = ('Login error: Provided password does not match records for that username or '
                   'username does not exist.')
            self._print(msg)
            return bottle.HTTPResponse(status=403, body=msg)

        # Make sure that the security level is supported
        security_level = request_dict.get(
            'SecurityLevel', user_record.get('SecurityLevel', self.allowed_security[0]))
        if 'ipaddr' in user_record.get('SecurityLevel') and 'ipaddr' not in security_level:
            security_level += '+ipaddr' # Force IP address verification if registration requests it
        user_record['SecurityLevel'] = security_level
        if security_level not in self.allowed_security:
            msg = 'Login error: Security level must be one of: %r' % list(self.allowed_security)
            self._print(msg)
            res = bottle.HTTPResponse(status=400, body=msg)
            return res
        elif not secure_data and ('hmac' in security_level or 'rsa' in security_level):
            msg = ('Login error: Security level requested requires secure data transfer but '
                   'plaintext was used instead')
            self._print(msg)
            res = bottle.HTTPResponse(status=400, body=msg)
            return res

        # Verify user password
        if 'Password' in user_record and user_record.get('Password') != str(hash(password)):
            msg = ('Login error: Provided password does not match records for that username or '
                   'username does not exist.')
            self._print(msg)
            return bottle.HTTPResponse(status=403, body=msg)

        # Get user's IP address from request
        ip_addr = bottle.request.environ.get('REMOTE_ADDR', '')
        if ip_addr != user_record.get('RemoteIpAddr'):
            if 'ipaddr' in security_level:
                msg = 'Login error: Registration IP address does not match login attempt.'
                self._print(msg)
                return bottle.HTTPResponse(status=403, body=msg)
            else:
                user_record['RemoteIpAddr'] = ip_addr

        # Provide user with a temporary token
        token_key = str(request_dict.get('Key') if secure_data else user_record.get('Key'))
        token_record = self._gen_token(username, security_level=security_level, key=token_key)
        user_record['Token'] = token_record['Token']

        # Update the user record
        user_cond = {'Username': username}
        user_record['Key'] = token_record.get('Key')
        user_record['LastLogin'] = str(time.time())
        user_record = self.pddb.upsert('bottleship_users', record=user_record, 
                                         where=user_cond, astype='dict')[0]

        # Depending on the security level, we may need to encrypt or sign the data
        user_record_json = self._dump_user_record(security_level, user_record)

        res = bottle.HTTPResponse(status=200, body=user_record_json)
        res.set_cookie('Token', token_record['Token'], path='/', expires=int(float(token_record.get('Expiry'))))
        return res

    def logout(self, token=None, cookie_only=True, _request_fallback=None):
        '''
        Expire a given token immediately.

        Parameters
        ----------
        token : str
            Token to immediately expire. This will be retrieved from the header cookies or from the
            request depending on the value of parameter `cookie_only`.
        cookie_only : bool
            If true, only retrieve Token from the header cookies. This is to prevent malicious
            users to log out other users; if this method is exposed in the application\'s API, this
            parameter should always be True (which is the default behavior).
        _request_fallback : dict
            Used for testing purposes.
            The parameter `Token` can also be passed to this method as items in the
            `_request_fallback` dictionary.
        '''

        # Try to retrieve the token from the cookies first
        token_cookie = bottle.request.get_cookie('Token')

        # If no token was found, retrieve it from the request data
        if not token_cookie and not cookie_only:
            request_dict = PandasDatabase._request(bottle.request, request_fallback=_request_fallback)
            token = token or request_dict.get('Token')
        else:
            token = str(token_cookie)

        # Verify that the token is provided in the request
        if token is None:
            msg = 'Auth error: "Token" field must be present as part of the request.'
            self._print(msg)
            return bottle.HTTPResponse(status=400, body=msg)

        # Validate the provided token against the token store
        token_record = self.pddb.find_one(
            'bottleship_tokens', where={'Token': token}, astype='dict')
        if not token_record or time.time() > float(token_record.get('Expiry', '0')):
            msg = 'Auth error: Provided token does not exist or has expired.'
            self._print(msg)
            return bottle.HTTPResponse(status=400, body=msg)

        # Expire token record in the database
        self.pddb.upsert('bottleship_tokens', where={'Token': token}, record={'Expiry': '0'})

        res = bottle.HTTPResponse(status=200, body='OK')
        res.set_cookie('Token', '', path='/', expires=0)
        return res

    def _authenticate(self, callback_success=None, callback_failure=None, token=None,
                      _request_fallback=None, **callback_success_kwargs):
        ''' Authenticate user with the user-provided token '''
        callback_success = callback_success or \
            (lambda: bottle.HTTPResponse(status=200, body='OK'))
        callback_failure = callback_failure or \
            (lambda code, err: bottle.HTTPResponse(status=code, body=err))
        callback_success_kwargs = callback_success_kwargs or dict()

        # Try to retrieve the token from the cookies first
        token_cookie = bottle.request.get_cookie('Token')

        # If no token was found, retrieve it from the request data
        if not token_cookie:
            request_dict = PandasDatabase._request(bottle.request, request_fallback=_request_fallback)
            token = token or request_dict.get('Token')
        else:
            token = str(token_cookie)

        # Verify that the token is provided in the request
        if token is None:
            msg = 'Auth error: "Token" field must be present as part of the request.'
            self._print(msg)
            return callback_failure(400, msg)

        # Validate the provided token against the token store
        token_record = self.pddb.find_one(
            'bottleship_tokens', where={'Token': token}, astype='dict')
        if not token_record or time.time() > float(token_record.get('Expiry', '0')):
            msg = 'Auth error: Provided token does not exist or has expired.'
            self._print(msg)
            return callback_failure(403, msg)

        # Retrieve the user record that the token belongs to
        user_record = self.pddb.find_one(
            'bottleship_users', where={'Username': token_record.get('Username')}, astype='dict')

        # If callback accepts it as an argument, add bottleship_user_record
        arg_spec = inspect.getargspec(callback_success)
        if 'bottleship_user_record' in arg_spec.args:
            callback_success_kwargs['bottleship_user_record'] = user_record

        # If token requires only plaintext security, we're done
        if 'plaintext' in token_record.get('SecurityLevel'):
            return callback_success(**callback_success_kwargs)

        # Depending on the security level, the data might need to be encrypted or signed
        elif 'hmac' in token_record.get('SecurityLevel'):
            key = token_record.get('Key')
            code, data = 200, callback_success(**callback_success_kwargs)
            if isinstance(data, bottle.HTTPResponse):
                code, data = data.status_code, data_encode(data.body, key)
            elif data:
                data = data_encode(data, key)
            return bottle.HTTPResponse(body=data, status=code)

    def require_auth(self, path=None, method='GET', callback_success=None, callback_failure=None,
                     name=None, apply=None, skip=None, **config):
        '''
        A decorator to bind a function to a request URL that requires authentication.

        Parameters
        ----------
        path : str
            Request path or a list of paths to listen to. If no path is specified, it is
            automatically generated from the signature of the function.
        method : str or list of str (default `GET`)
            HTTP method (`GET`, `POST`, `PUT`, ...) or a list of methods to listen to.
        callback_success : func (default ``lambda: bottle.HTTPResponse(status=200, body="OK")``
            An optional shortcut to avoid the decorator syntax. To use the default, pass `False` as
            the value to this argument.
        callback_failure : func (default ``lambda code, err: bottle.HTTPResponse(status=code, body=err)``
            Function to call when there is an error authenticating the user token. The function
            must take exactly 2 parameters: status_code and error_message.
        name : See bottle.Bottle for more information.
        apply : See bottle.Bottle for more information.
        skip : See bottle.Bottle for more information.

        Any additional keyword arguments are stored as route-specific
        configuration and passed to plugins (see `Plugin.apply`).

        Returns
        -------
        decorator : func
            Decorator function.

        Examples
        --------
        >>> app = BottleShip()
        >>> @app.require_auth('/hello/<name>')
        ... def hello(name):
        ...     return 'Hello, %s!' % name
        >>> app.require_auth('/hello', callback_success=lambda: "Hello, anonymous user!")
            <function BottleShip.require_auth.<locals>.decorator.<locals>.<lambda> at 0x0000000004C62840>
        '''
        if not callback_success and 'callback' in config.keys():
            callback_success = config.pop('callback')
        def decorator(callback):
            route_do = lambda **kwargs: self._authenticate(
                callback_success=callback, callback_failure=callback_failure, **kwargs)
            return self.route(path, method, route_do, name, apply, skip, **config)
        return decorator(callback_success) if callback_success is not None else decorator

def main(args):

    parser = argparse.ArgumentParser(description=('Start a test server'))
    parser.add_argument('--port', type=int, default=8080,
                        help='http port where the server exposes its API')
    args = parser.parse_args(args)

    bs = BottleShip()
    bs.route('/', callback=lambda: bottle.static_file('login.html', root='examples'))
    
    bs.route('/register', method=('GET', 'POST'), callback=bs.register)
    bs.route('/login', method=('GET', 'POST'), callback=bs.login)
    bs.route('/logout', method=('GET', 'POST'), callback=bs.logout)
    bs.route(
        '/swapkeys/<security_level>/<user_key>', method=('GET', 'POST'), callback=bs.key_exchange)

    # Test API route using default callback
    bs.require_auth('/test', method=('GET', 'POST'), callback_success=False)

    # Test API route using decorator
    @bs.require_auth('/hello/<name>', method=('GET', 'POST'))
    def testapi2(name):
        return 'Hello, %s!' % name

    # Test API route using bottleship_user_record parameter
    bs.require_auth('/hellome', method=('GET', 'POST'), callback_success=\
        lambda bottleship_user_record: 'Hello, %s!' % bottleship_user_record.get('Username'))

    # Test API route using bottleship_user_record parameter and decorator
    @bs.require_auth('/whoami', method=('GET', 'POST'))
    def testapi4(bottleship_user_record):
        return '%s' % bottleship_user_record

    try:
        bs.run(host='0.0.0.0', port=args.port, debug=True)
    finally:
        bs.pddb.drop_all()

if __name__ == "__main__":
    main(sys.argv[1:])
