===============================
BottleShip
===============================

.. image:: https://img.shields.io/pypi/v/bottleship.svg
        :target: https://pypi.python.org/pypi/bottleship

.. image:: https://img.shields.io/travis/omtinez/bottleship.svg
        :target: https://travis-ci.org/omtinez/bottleship

.. image:: https://readthedocs.org/projects/bottleship/badge/?version=latest
        :target: https://readthedocs.org/projects/bottleship/?badge=latest
        :alt: Documentation Status


Authentication for the Bottle web framework made simple.

* Free software: MIT license
* Documentation: https://bottleship.readthedocs.org.

Introduction
------------

BottleShip is a very simple library for authentication using the Bottle web framework. It supports
the standard workflow of registration, login, and authentication required by simple applications
that need to maintain a state for individual users.

Features
--------

* Very simple and easy to use
* Works both on Python 2.x and 3.x
* Very few dependencies

Getting Started
---------------

This documentation assumes that you already have a working Bottle application or that you are
somewhat familiar with the Bottle web framework. If you need to reference documentation for Bottle,
`here is the link`_.

The easiest way to install BottleShip is using pip::

    $ pip install bottleship

With BottleShip installed, this is what it takes to use authentication to lock certain routes so
they can only be used by users who are logged in:

.. code:: python

    # Instantiate class and register "register" and "login" routes
    bs = BottleShip()
    bs.route('/register', method=('GET', 'POST'), callback=bs.register)
    bs.route('/login', method=('GET', 'POST'), callback=bs.login)
    
    # This API endpoint can only be reached by users who have logged in
    @bs.require_auth('/testapi', method=('GET', 'POST'))
    def testapi(bottleship_user_record):
        return "Hello, %s!" % bottleship_user_record.get('Username')

New users can register by visiting the ``/register`` endpoint and sending their ``username`` and
``password`` as part of their request. For example, a new user can be registered with the following
request:

    >>> curl http://127.0.0.1:8080/register?Username=john&Password=1234
    ... HTTP/1.0 200 OK
    ... Content-Length: 155
    ... Content-Type: text/html; charset=UTF-8
    ... Date: Sun, 17 Jan 2016 23:36:02 GMT
    ... Server: WSGIServer/0.1 Python/2.7.10
    ... 
    ... {"Username": "john", "SecurityLevel": "plaintext", "Password": "1723328
    ... 704", "RemoteIpAddr": "127.0.0.1", "__id__": "040220e5-1cce-4cdd-af9d-2
    ... ad2885263aa"}

Similarly, to log in, a user can make the following request:

    >>> curl http://127.0.0.1:8080/login?Username=john&Password=1234
    ... HTTP/1.0 200 OK
    ... Content-Length: 247
    ... Content-Type: text/html; charset=UTF-8
    ... Date: Sun, 17 Jan 2016 23:36:03 GMT
    ... Set-Cookie: Token=5f04ee43-83bb-46c0-96aa-65a2c585a796; Path=/
    ... Server: WSGIServer/0.1 Python/2.7.10
    ... 
    ... {"Username": "john", "SecurityLevel": "plaintext", "LastLogin": "145307
    ... 3842.72", "Token": "5f04ee43-83bb-46c0-96aa-65a2c585a796", "__id__": "0
    ... 40220e5-1cce-4cdd-af9d-2ad2885263aa", "Key": null, "Password": "1723328
    ... 704", "RemoteIpAddr": "127.0.0.1"}

Both requests will return a JSON object that represents a record with all the information that the
BottleShip server has about the user. A login request\'s returned JSON also has a field named
``Token`` that contains the user session token. In addition to that, the returned request will
also store the session token as part of the cookies in the request headers.

If the login was successful, the user can now make the following request:

    >>> curl http://127.0.0.1:8080/testapi3?Token=5f04ee43-83bb-46c0-96aa-65a2c
        585a796
    ... HTTP/1.0 200 OK
    ... Content-Length: 12
    ... Content-Type: text/html; charset=UTF-8
    ... Date: Sun, 17 Jan 2016 23:36:04 GMT
    ... Server: WSGIServer/0.1 Python/2.7.10
    ... 
    ... Hello, john!

If everything worked, the user will receive ``Hello, john!``.

Security
--------

Needless to say, you should not be transmitting passwords over a plain connection like it is done
in the example above. If you cannot achieve a cryptographically secure connection between user and
server, your only hope is to implement a public key scheme to allow for secure transmission of user
password and token. Such scheme is not implemented in BottleShip, but it has a few mitigations in
place that yield a marginal increase in security.

When registration takes place, all information provided by the user is recorded. Most of it is
provided by the user himself so it could be easily forged, but the IP address is slightly more
difficult to fake. Using the user IP address, along with some form of whitelisting (or
blacklisting), allows for a relative improvement in the application security. To achieve this, one
must provide the whitelist upon instantiation like:

.. code:: python

    valid_users = {"RemoteIpAddr": "127.0.0.1"}
    bs = BottleShip(whitelist_cond=valid_users)
    
Then, when the user registers, BottleShip will make sure that only requests from the provided IP
addresses have permission to reach the endpoint.

Another mitigation regarding the user IP address is the verification of addresses not changing
between registration and login. This is achieved by appending ``+ipaddr`` to the desired security
level upon registration. For example, a new user can be registered with the following request:

    >>> curl http://127.0.0.1:8080/register?Username=john&Password=1234&Securit
        yLevel=plaintext%2Bipaddr
    ... HTTP/1.0 200 OK
    ... Content-Length: 162
    ... Content-Type: text/html; charset=UTF-8
    ... Date: Sun, 17 Jan 2016 23:36:05 GMT
    ... Server: WSGIServer/0.1 Python/2.7.10
    ... 
    ... {"Username": "john", "SecurityLevel": "plaintext+ipaddr", "Password": "
    ... 1723328704", "RemoteIpAddr": "127.0.0.1", "__id__": "1b5ca834-f4fb-4f6a
    ... -96f3-5a427ca43270"}

Note that the ``+`` sign is URL encoded so ``plaintext`` becomes ``plaintext+ipaddr``, which is
encoded into ``plaintext%2Bipaddr``. IP address verification is the only security feature that will
persist between registration and login. Other than that, the security level during login can be
whatever the client chooses regardless of the security level during registration.

A more sophisticated security mitigation is implementing HMAC signing for the information exchanged
between client and server during registration and login. This requires an additional step to
perform the key exchange prior to registration and/or login. The key exchange will provide the user
with a single-use token that can be utilized by the client to send the server information signed
with the secret key provided during the exchange.

    >>> curl http://127.0.0.1:8080/swapkeys/hmac/5f04ee43-83bb-46c0-96aa-65a2c5
        85a796
    ... HTTP/1.0 200 OK
    ... Content-Length: 114
    ... Content-Type: text/html; charset=UTF-8
    ... Date: Sun, 17 Jan 2016 23:36:06 GMT
    ... Server: WSGIServer/0.1 Python/2.7.10
    ... 
    ... !1ICg4mv4H8NGUyV5aveJU1fJ/wnFr0cOks+KMIvZuIo=?eyJUb2tlbiI6ICI0OGYyNWM4O
    ... S1mZDg2LTRhMzctOGYyNi00NmYxNmE0YzVlYWIifQ==

Note that the token is encoded in base64 and later signed with the user-provided key. Decoding the
above string produces ``{"Token": "48f25c89-fd86-4a37-8f26-46f16a4c5eab"}``.

Which can then be hashed and the signature verified using the user-provided secret key. In the next
step, the client can send all the user information encoded and signed along with the single-use
token so the server knows which key to verify the data with:

    >>> curl http://127.0.0.1:8080/register?Token=48f25c89-fd86-4a37-8f26-46f16
        a4c5eab&Data=!6uz1tJzSZX%2F0EhVqj4ZpTMiiNmONVPY601ZHCHLXu9M%3D%3FeyJVc2
        VybmFtZSI6ImpvaG4iLCJQYXNzd29yZCI6IjEyMzQifQ%3D%3D
    ... HTTP/1.0 200 OK
    ... Content-Length: 202
    ... Content-Type: text/html; charset=UTF-8
    ... Date: Sun, 17 Jan 2016 23:36:07 GMT
    ... Server: WSGIServer/0.1 Python/2.7.10
    ... 
    ... {"Username": "john", "SecurityLevel": "plaintext", "__id__": "3be4ed1c-
    ... d30d-4786-bfc7-97728120e7b2", "Key": "5f04ee43-83bb-46c0-96aa-65a2c585a
    ... 796", "Password": "1723328704", "RemoteIpAddr": "127.0.0.1"}

The data returned by the server is in plaintext because a security level was not specified in the
request. If the client wants the user information encoded, he must explicitly specify a security
level that enforces signature verification.

The only other method in the authentication workflow other than registration that supports encoding
is login. The function signature is identical and the token is also of single-use. After login, any
further references of ``token`` in the APIs assume that it is the session token. It is worth noting
that, because the token and user key are expected to last as long as the session does, it is
pointless to encode, hash, or otherwise obscure the token or user key. Since the same string,
encrypted or otherwise, will be sent in each request by the client, it makes no difference to an
attacker to sniff the plaintext version or the encrypted version of the token; he can just present
the server with the same string and it will be accepted as valid. For similar reasons, the password
is being sent in plaintext form to the server and it is only hashed internally.

License
-------

Copyright (c) 2016 Oscar Martinez
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

.. _here is the link: http://bottlepy.org/docs/dev/api.html
