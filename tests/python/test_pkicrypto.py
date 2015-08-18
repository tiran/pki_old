# -*- coding: utf-8 -*-
# Authors:
#     Christian Heimes <cheimes@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

import os
import shutil
import tempfile
import unittest

from nss import nss
from nss.error import NSPRError

from pki.crypto import NSSCryptoProvider


class PKICryptoTests(unittest.TestCase):
    password = b'random password'

    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.mkdtemp()
        cls.dbdir = os.path.join(cls.tempdir, 'nssdb')
        NSSCryptoProvider.setup_database(cls.dbdir, cls.password)
        cls.provider = NSSCryptoProvider(cls.dbdir, cls.password)
        cls.provider.initialize()

    @classmethod
    def tearDownClass(cls):
        nss.nss_shutdown()
        shutil.rmtree(cls.tempdir)

    def test_generate_nounce_iv(self):
        iv = self.provider.generate_nonce_iv()
        self.assertIsInstance(iv, bytes)
        self.assertEqual(len(iv), 8)

        iv = self.provider.generate_nonce_iv(nss.CKM_AES_CBC_PAD)
        self.assertIsInstance(iv, bytes)
        self.assertEqual(len(iv), 16)

    def test_generate_symmentric_key(self):
        key = self.provider.generate_symmetric_key()
        self.assertIsInstance(key, nss.PK11SymKey)
        self.assertEqual(key.key_length, 24)

        key = self.provider.generate_symmetric_key(nss.CKM_AES_CBC_PAD)
        self.assertIsInstance(key, nss.PK11SymKey)
        self.assertEqual(key.key_length, 32)

    def test_generate_session_key(self):
        key = self.provider.generate_session_key()
        self.assertIsInstance(key, nss.PK11SymKey)
        self.assertEqual(key.key_length, 24)

    def test_symmentric_wrap(self):
        key = self.provider.generate_symmetric_key()
        data = b'some private data'
        wrapped = self.provider.symmetric_wrap(data, key)
        self.assertNotEqual(data, wrapped)
        unwrapped = self.provider.symmetric_unwrap(wrapped, key)
        self.assertEqual(data, unwrapped)

        otherkey = self.provider.generate_symmetric_key()
        with self.assertRaises(NSPRError) as e:
            self.provider.symmetric_unwrap(wrapped, otherkey)
        self.assertEqual(
            e.exception.error_desc,
            '(SEC_ERROR_BAD_DATA) security library: received bad data.'
        )


if __name__ == '__main__':
    unittest.main()
