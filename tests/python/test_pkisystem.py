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

import six

from pki import system

from pkitestbase import PKITestCase


class PKISystemTests(PKITestCase):

    def test_get_security_domain_info(self):
        client = system.SecurityDomainClient(self.connection)
        info = client.get_security_domain_info()
        self.assertIsInstance(info, system.SecurityDomainInfo)
        self.assertEqual(info.name, self.security_domain)
        self.assertEqual(sorted(info.systems), ['CA', 'KRA'])

        ca = info.systems['CA']
        self.assertIsInstance(ca, system.SecurityDomainSubsystem)
        self.assertEqual(ca.name, u'CA')
        self.assertEqual(len(ca.hosts), 1)

        hostkey = list(ca.hosts)[0]
        host = ca.hosts[hostkey]
        self.assertIsInstance(host, system.SecurityDomainHost)
        self.assertEqual(host.secure_port, str(self.port))

    def test_get_status(self):
        client = system.SystemStatusClient(self.connection)
        status = client.get_status()
        self.assertIsInstance(status, six.text_type)
        self.assertIn('<XMLResponse>', status)


if __name__ == '__main__':
    unittest.main()
