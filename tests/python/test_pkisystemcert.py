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

from pki.cert import CertData
from pki.systemcert import SystemCertClient

from pkitestbase import PKITestCase


class PKISystemTests(PKITestCase):

    def test_get_transport_cert(self):
        client = SystemCertClient(self.connection)
        cert = client.get_transport_cert()
        self.assertIsInstance(cert, CertData)
        self.assertEqual(
            cert.subject_dn,
            u'CN=DRM Transport Certificate,O=%s' % self.security_domain
        )
        self.assertEqual(
            cert.issuer_dn,
            u'CN=CA Signing Certificate,O=%s' % self.security_domain
        )
        self.assertIsInstance(cert.encoded, six.text_type)
        self.assertTrue(cert.encoded)


if __name__ == '__main__':
    unittest.main()
