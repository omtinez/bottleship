#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_bottleship_auth
----------------------------------

Tests for `bottleship` module regarding authentication.
"""

import uuid
import json
import unittest

import bottle
from pddb import PandasDatabase

import bottleship
from bottleship import BottleShip


class TestBottleshipAuth(unittest.TestCase):

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
        token = str(json.loads(bottleship.data_decode(res.body, key)).get('Token'))

        user_info = user_info if isinstance(user_info, str) else json.dumps(user_info)
        req = {'Data': bottleship.data_encode(json.dumps(user_info), key), 'Token': token}
        res = self.app.login(_request_fallback=req)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        return json.loads(bottleship.data_decode(res.body, key))


    ### Authenticate tests ###

    def test_authenticate_default(self):
        name = self.id()
        res = self.app.register(username=name)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)
        token = str(json.loads(res.body).get('Token'))

        res = self.app._authenticate(token=token)
        self.assertEqual(res.status_code, 200)

    def test_authenticate_plaintext(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext'}
        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)
        token = str(json.loads(res.body).get('Token'))

        res = self.app._authenticate(token=token)
        self.assertEqual(res.status_code, 200)

    def test_authenticate_ipaddr(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext+ipaddr'}
        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)
        token = str(json.loads(res.body).get('Token'))

        res = self.app._authenticate(token=token)
        self.assertEqual(res.status_code, 200)

    def test_authenticate_hmac(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))
        token = str(user_info.get('Token'))

        res = self.app._authenticate(token=token)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))

    def test_authenticate_hmac_ipaddr(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))
        token = str(user_info.get('Token'))

        res = self.app._authenticate(token=token)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))


    ### Authenticate wrong token tests ###

    def test_authenticate_wrong_token_default(self):
        name = self.id()
        res = self.app.register(username=name)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)
        token = str(json.loads(res.body).get('Token'))

        res = self.app._authenticate(token='1234')
        self.assertEqual(res.status_code, 403)

    def test_authenticate_wrong_token_plaintext(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext'}
        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)
        token = str(json.loads(res.body).get('Token'))

        res = self.app._authenticate(token='1234')
        self.assertEqual(res.status_code, 403)

    def test_authenticate_wrong_token_ipaddr(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext+ipaddr'}
        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.login(username=name)
        self.assertEqual(res.status_code, 200)
        token = str(json.loads(res.body).get('Token'))

        res = self.app._authenticate(token='1234')
        self.assertEqual(res.status_code, 403)

    def test_authenticate_wrong_token_hmac(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))
        token = str(user_info.get('Token'))

        res = self.app._authenticate(token='1234')
        self.assertEqual(res.status_code, 403)
        self.assertFalse(bottleship.data_is_encoded(res.body))

    def test_authenticate_wrong_token_hmac_ipaddr(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}
        user_info = self.register_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))

        key = '5678'
        user_info = self.login_hmac(data, key)
        self.assertEqual(user_info.get('SecurityLevel'), data.get('SecurityLevel'))
        token = str(user_info.get('Token'))

        res = self.app._authenticate(token='1234')
        self.assertEqual(res.status_code, 403)
        self.assertFalse(bottleship.data_is_encoded(res.body))


    ### Whitelisting and blacklisting tests ###

    # TODO

if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
