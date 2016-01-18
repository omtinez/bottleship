#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_bottleship_register
----------------------------------

Tests for `bottleship` module regarding registration.
"""

import uuid
import json
import unittest

import bottle
from pddb import PandasDatabase

import bottleship
from bottleship import BottleShip


class TestBottleshipRegister(unittest.TestCase):

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

    def test_security_unsupported(self):
        res = self.app.register(user_info={'SecurityLevel': None})
        self.assertEqual(res.status_code, 400)


    ### Register tests ###

    def test_register_without_password_default(self):
        name = self.id()
        res = self.app.register(username=name)
        self.assertEqual(res.status_code, 200)

    def test_register_without_password_plaintext(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext', 'CustomField': name}
        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)
        user_info = json.loads(res.body)
        for k,v in req.items():
            self.assertEqual(user_info.get(k), req.get(k))

    def test_register_without_password_ipaddr(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext+ipaddr', 'CustomField': name}
        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)
        user_info = json.loads(res.body)
        for k,v in req.items():
            self.assertEqual(user_info.get(k), req.get(k))

    def test_register_without_password_hmac(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac', 'CustomField': name}
        user_info = self.register_hmac(data, key)
        for k,v in data.items():
            self.assertEqual(user_info.get(k), data.get(k))

    def test_register_without_password_hmac_ipaddr(self):
        name = self.id()
        key = '1234'
        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr', 'CustomField': name}
        user_info = self.register_hmac(data, key)
        for k,v in data.items():
            self.assertEqual(user_info.get(k), data.get(k))

    def test_register_with_password_default(self):
        name = self.id()
        password = self.id()
        res = self.app.register(username=name, password=password)
        self.assertEqual(res.status_code, 200)

    def test_register_with_password_plaintext(self):
        name = self.id()
        password = self.id()
        req = {'SecurityLevel': 'plaintext', 'CustomField': name}
        res = self.app.register(username=name, password=password, user_info=req)
        self.assertEqual(res.status_code, 200)
        user_info = json.loads(res.body)
        for k,v in req.items():
            self.assertEqual(user_info.get(k), req.get(k))

    def test_register_with_password_ipaddr(self):
        name = self.id()
        password = self.id()
        req = {'SecurityLevel': 'plaintext+ipaddr', 'CustomField': name}
        res = self.app.register(username=name, password=password, user_info=req)
        self.assertEqual(res.status_code, 200)
        user_info = json.loads(res.body)
        for k,v in req.items():
            self.assertEqual(user_info.get(k), req.get(k))

    def test_register_with_password_hmac(self):
        name = self.id()
        password = self.id()
        key = '1234'
        data = {'Username': name, 'Password': password, 'SecurityLevel': 'hmac', 'CustomField': name}
        user_info = self.register_hmac(data, key)
        for k,v in data.items():
            if k == 'Password': continue
            self.assertEqual(user_info.get(k), data.get(k))

    def test_register_with_password_hmac_ipaddr(self):
        name = self.id()
        password = self.id()
        key = '1234'
        data = {'Username': name, 'Password': password, 'SecurityLevel': 'hmac+ipaddr', 'CustomField': name}
        user_info = self.register_hmac(data, key)
        for k,v in data.items():
            if k == 'Password': continue
            self.assertEqual(user_info.get(k), data.get(k))

    def test_register_fail_default(self):
        name = self.id()
        res = self.app.register(username=name, password=object())
        self.assertEqual(res.status_code, 400)

        res = self.app.register(username=name)
        self.assertEqual(res.status_code, 200)

        name = self.id()
        res = self.app.register(username=name)
        self.assertEqual(res.status_code, 400)

        name = self.id()
        res = self.app.register(username='')
        self.assertEqual(res.status_code, 400)

        name = self.id()
        res = self.app.register(username=object())
        self.assertEqual(res.status_code, 400)

        name = self.id()
        res = self.app.register()
        self.assertEqual(res.status_code, 400)

    def test_register_fail_plaintext(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext'}
        res = self.app.register(username=name, password=object(), user_info=req)
        self.assertEqual(res.status_code, 400)

        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.register(username='', user_info=req)
        self.assertEqual(res.status_code, 400)

        res = self.app.register(username=object(), user_info=req)
        self.assertEqual(res.status_code, 400)

        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)

    def test_register_fail_ipaddr(self):
        name = self.id()
        req = {'SecurityLevel': 'plaintext+ipaddr', 'CustomField': name}
        res = self.app.register(username=name, password=object(), user_info=req)
        self.assertEqual(res.status_code, 400)

        res = self.app.register(username=name, user_info=req)
        self.assertEqual(res.status_code, 200)

        res = self.app.register(username='', user_info=req)
        self.assertEqual(res.status_code, 400)

        res = self.app.register(username=object(), user_info=req)
        self.assertEqual(res.status_code, 400)

        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)

    def test_register_fail_hmac(self):
        name = self.id()
        key = '1234'
        res = self.app.key_exchange('hmac', key)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        token = str(json.loads(bottleship.data_decode(res.body, key)).get('Token'))

        #data = {'Username': None, 'SecurityLevel': 'hmac'}
        ##req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        #res = self.app.register(user_info=req)
        #self.assertEqual(res.status_code, 400)
        #self.assertTrue(bottleship.data_is_encoded(res.body))

        data = {'Username': name, 'SecurityLevel': 'hmac'}
        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': '1234'}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        data = {'Username': name, 'SecurityLevel': 'hmac'}
        req = {'Data': '1234', 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        data = {'Username': name, 'SecurityLevel': 'hmac'}
        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        res = self.app.key_exchange('hmac', key)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        token = str(json.loads(bottleship.data_decode(res.body, key)).get('Token'))
        data = {'Username': name, 'SecurityLevel': 'hmac'}
        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))

        data = {'Username': name, 'SecurityLevel': 'hmac'}
        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

    def test_register_fail_hmac_ipaddr(self):
        name = self.id()
        key = '1234'
        res = self.app.key_exchange('hmac', key)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        token = str(json.loads(bottleship.data_decode(res.body, key)).get('Token'))

        #data = {'Username': None, 'SecurityLevel': 'hmac+ipaddr'}
        #req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        #res = self.app.register(user_info=req)
        #self.assertEqual(res.status_code, 400)
        #self.assertFalse(bottleship.data_is_encoded(res.body))

        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}
        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': '1234'}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}
        req = {'Data': '1234', 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}
        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

        res = self.app.key_exchange('hmac+ipaddr', key)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))
        token = str(json.loads(bottleship.data_decode(res.body, key)).get('Token'))
        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}
        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(bottleship.data_is_encoded(res.body))

        data = {'Username': name, 'SecurityLevel': 'hmac+ipaddr'}
        req = {'Data': bottleship.data_encode(json.dumps(data), key), 'Token': token}
        res = self.app.register(user_info=req)
        self.assertEqual(res.status_code, 400)
        self.assertFalse(bottleship.data_is_encoded(res.body))

if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
