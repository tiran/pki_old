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

from pki.kra import KRAClient
from pki.key import KeyClient
from pki.systemcert import SystemCertClient

from pkitestbase import PKICryptoTestCase


class PKIKRAClientTests(PKICryptoTestCase):
    subsystem = 'kra'

    def test_kraclient(self):
        client = KRAClient(self.connection, self.crypto)
        self.assertIs(client.crypto, self.crypto)
        self.assertIsInstance(client.keys, KeyClient)
        self.assertIsInstance(client.system_certs, SystemCertClient)


if __name__ == '__main__':
    unittest.main()