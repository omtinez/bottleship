#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_bottleship_login
----------------------------------

Tests for `bottleship` module regarding login.
"""

import uuid
import json
import unittest

import bottle
from pddb import PandasDatabase

import bottleship
from bottleship import BottleShip


class TestBottleshipLogin(unittest.TestCase):

    def setUp(self):
        db = PandasDatabase(str(uuid.uuid4()))
        self.app = BottleShip(pddb=db, debug=True)

    def tearDown(self):
        self.app.pddb.drop_all()


    ### Utility functions ###

    def register_hmac(self, user_info, key):
        res = self.app.key_exchange('hmac', key)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        token = str(json.loads(bottleship.data_decode(res.body, key)).get('Token'))

        user_info = user_info if isinstance(user_info, str) else json.dumps(user_info)
        req = {'Data': bottleship.data_encode(json.dumps(user_info), key), 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        return json.loads(bottleship.data_decode(res.body, key))

    def login_hmac(self, user_info, key):
        res = self.app.key_exchange('hmac', key)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        token = json.loads(bottleship.data_decode(res.body, key)).get('Token')

        user_info = user_info if isinstance(user_info, str) else json.dumps(user_info)
        req = {'Data': bottleship.data_encode(json.dumps(user_info), key), 'Token': token}
        res = self.app.login(_request_fallback=req)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        return json.loads(bottleship.data_decode(res.body, key))

    def test_login_wrong_username_default(self):
        res = self.app.login()
        self.assertEqual(res.status_code, 400)

        res = self.app.login(username='')
        self.assertEqual(res.status_code, 400)

        res = self.app.login(username=object())
        self.assertEqual(res.status_code, 400)

        res = self.app.login(username='1234')
        self.assertEqual(res.status_code, 403)

   
    ### Login without password tests ###

    def test_login_without_password_default(self):
        name = self.id()
        res = self.app.register(username=name)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), 'plaintext')

    def test_login_without_password_plaintext(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext'}
        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, _request_fallback=req)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), req.get('SecurityLevel'))

    def test_login_without_password_ipaddr(self):
        name = self.id()
        req = {'SecurityLevel':'plaintext+ipaddr'}
        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), req.get('SecurityLevel'))

    def test_login_without_password_hmac(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        json_str = '{' + ','.join(['"%s":"%s"' % (k,v) for k,v in data.items()]) + '}' 
        user_info = self.login_hmac(json_str, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        # Switch to plaintext and try login again
        req = {'Username': name, 'SecurityLevel': 'plaintext'}
        res = self.app.login(username=name, _request_fallback=req)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), req.get('SecurityLevel'))

    def test_login_without_password_hmac_ipaddr(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        json_str = '{' + ','.join(['"%s":"%s"' % (k,v) for k,v in data.items()]) + '}' 
        user_info = self.login_hmac(json_str, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        # Switch to plaintext and try login again
        req = {'Username': name, 'SecurityLevel': 'plaintext'}
        res = self.app.login(username=name, _request_fallback=req)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), req.get('SecurityLevel') + '+ipaddr')

   
    ### Login with password tests ###

    def test_login_with_password_default(self):
        name = self.id()
        password = self.id()
        res = self.app.register(username=name, password=password)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=password)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), 'plaintext')

    def test_login_with_password_plaintext(self):
        name = self.id()
        password = self.id()
        req = {'SecurityLevel': 'plaintext'}
        res = self.app.register(username=name, password=password, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=password)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), req.get('SecurityLevel'))

    def test_login_with_password_ipaddr(self):
        name = self.id()
        password = self.id()
        req = {'SecurityLevel': 'plaintext+ipaddr'}
        res = self.app.register(username=name, password=password, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=password)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), req.get('SecurityLevel'))

    def test_login_with_password_hmac(self):
        name = self.id()
        password = self.id()
        key = '1234'
        data = {'Username': name, 'Password': password, 'SecurityLevel': 'hmac'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        json_str = '{' + ','.join(['"%s":"%s"' % (k,v) for k,v in data.items()]) + '}' 
        user_info = self.login_hmac(json_str, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

    def test_login_with_password_hmac_ipaddr(self):
        name = self.id()
        password = self.id()
        key = '1234'
        data = {'Username': name, 'Password': password, 'SecurityLevel': 'hmac+ipaddr'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        json_str = '{' + ','.join(['"%s":"%s"' % (k,v) for k,v in data.items()]) + '}' 
        user_info = self.login_hmac(json_str, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

   
    ### Login empty password tests ###

    def test_login_empty_password_default(self):
        name = self.id()
        password = ''
        res = self.app.register(username=name, password=password)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=None)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=password)
        self.assertEqual(res.status_code, 200)

    def test_login_empty_password_plaintext(self):
        name = self.id()
        password = ''
        req = {'SecurityLevel': 'plaintext'}
        res = self.app.register(username=name, password=password, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, _request_fallback=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=None, _request_fallback=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=password, _request_fallback=req)
        self.assertEqual(res.status_code, 200)

    def test_login_empty_password_ipaddr(self):
        name = self.id()
        password = self.id()
        req = {'SecurityLevel': 'plaintext+ipaddr'}
        res = self.app.register(username=name, password='', user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, _request_fallback=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=None, _request_fallback=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password='', _request_fallback=req)
        self.assertEqual(res.status_code, 200)

    def test_login_empty_password_hmac(self):
        name = self.id()
        password = ''
        key = '1234'
        data = {'Username': name, 'Password': '', 'SecurityLevel': 'hmac'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        json_str = '{' + ','.join(['"%s":"%s"' % (k,v) for k,v in data.items()]) + '}' 
        user_info = self.login_hmac(json_str, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

    def test_login_empty_password_hmac_ipaddr(self):
        name = self.id()
        password = ''
        key = '1234'
        data = {'Username': name, 'Password': '', 'SecurityLevel': 'hmac+ipaddr'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        json_str = '{' + ','.join(['"%s":"%s"' % (k,v) for k,v in data.items()]) + '}' 
        user_info = self.login_hmac(json_str, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

   
    ### Login wrong password tests ###

    def test_login_wrong_password_default(self):
        name = self.id()
        password = self.id()
        res = self.app.register(username=name, password=password)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password='1234')
        self.assertEqual(res.status_code, 403)

    def test_login_wrong_password_plaintext(self):
        name = self.id()
        password = self.id()
        req = {'SecurityLevel': 'plaintext'}
        res = self.app.register(username=name, password=password, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name, password=object())
        self.assertEqual(res.status_code, 400)

        res = self.app.login(username=name, password='1234')
        self.assertEqual(res.status_code, 403)

    def test_login_wrong_password_ipaddr(self):
        name = self.id()
        password = self.id()
        req = {'SecurityLevel': 'plaintext+ipaddr'}
        res = self.app.register(username=name, password=password, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.register(username=name, password=object(), user_info=req)
        self.assertEqual(res.status_code, 400)

        res = self.app.login(username=name, password='1234')
        self.assertEqual(res.status_code, 403)

    def test_login_wrong_password_hmac(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'Password': '', 'SecurityLevel': 'hmac'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        res = self.app.login(username=name, _request_fallback=data)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        res = self.app.login(username=name, password='', _request_fallback=data)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        res = self.app.login(username=name, password=object(), _request_fallback=data)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        res = self.app.login(username=name, password='1234', _request_fallback=data)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

    def test_login_wrong_password_hmac_ipaddr(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'Password': '', 'SecurityLevel': 'hmac+ipaddr'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        res = self.app.login(username=name, _request_fallback=data)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        res = self.app.login(username=name, password='', _request_fallback=data)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        res = self.app.login(username=name, password=object(), _request_fallback=data)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        res = self.app.login(username=name, password='1234', _request_fallback=data)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))


    ### Login new IP tests ###

    def test_login_newip_default(self):
        name = self.id()

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')

        res = self.app.register(username=name)
        self.assertEqual(res.status_code, 200)

        bottle.request.environ['REMOTE_ADDR'] = '1234'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '1234')

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')

    def test_login_newip_plaintext(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext'}

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')

        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        bottle.request.environ['REMOTE_ADDR'] = '1234'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '1234')

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')

    def test_login_newip_ipaddr(self):
        name = self.id()
        req = {'SecurityLevel':'plaintext+ipaddr'}

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')

        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        bottle.request.environ['REMOTE_ADDR'] = '1234'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '1234')

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 403)

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')

    def test_login_newip_hmac(self):
        name = self.id()
        password = ''
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac'}

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')

        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        bottle.request.environ['REMOTE_ADDR'] = '1234'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '1234')

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        # Switch to plaintext and try login again
        req = {'Username': name, 'SecurityLevel': 'plaintext'}
        res = self.app.login(username=name, _request_fallback=req)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.body).get('SecurityLevel'), req.get('SecurityLevel'))

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')


    def test_login_newip_hmac_ipaddr(self):
        name = self.id()
        password = ''
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')

        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        bottle.request.environ['REMOTE_ADDR'] = '1234'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '1234')

        key = '5678'
        res = self.app.key_exchange('hmac', key)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        token = str(json.loads(bottleship.data_decode(res.body, key)).get('Token'))

        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        res = self.app.login(_request_fallback=req)
        self.assertEqual(res.status_code, 403)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        # Switch to plaintext and try login again
        req = {'Username': name, 'SecurityLevel': 'plaintext'}
        res = self.app.login(username=name, _request_fallback=req)
        self.assertEqual(res.status_code, 403)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        bottle.request.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(bottle.request.environ['REMOTE_ADDR'], '127.0.0.1')


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
