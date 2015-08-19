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

from pki.account import AccountClient

from pkitestbase import PKITestCase


class PKIAccountTests(PKITestCase):
    def setUp(self):
        super(PKIAccountTests, self).setUp()
        self.client = AccountClient(self.connection)

    def test_login(self):
        cookies = self.connection.session.cookies
        self.assertNotIn('JSESSIONID', cookies)
        self.client.login()
        self.assertIn('JSESSIONID', cookies)
        self.client.logout()


if __name__ == '__main__':
    unittest.main()