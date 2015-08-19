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

import unittest

from pki import key as pkikey
from pki.account import AccountClient

from pkitestbase import PKICryptoTestCase


class PKIKeyClientTests(PKICryptoTestCase):
    subsystem = 'kra'

    def setUp(self):
        super(PKIKeyClientTests, self).setUp()
        self.kra_account = AccountClient(self.connection)
        self.kra_account.login()
        self.client = pkikey.KeyClient(self.connection, self.crypto)

    def tearDown(self):
        self.kra_account.logout()
        super(PKIKeyClientTests, self).tearDown()

    def test_list_keys(self):
        keys = self.client.list_keys()
        self.assertIsInstance(keys, pkikey.KeyInfoCollection)

    def test_list_requests(self):
        requests = self.client.list_requests()
        self.assertIsInstance(requests, pkikey.KeyRequestInfoCollection)


if __name__ == '__main__':
    unittest.main()
