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

from __future__ import print_function

__all__ = ('PKITestCase', 'PKICryptoTestCase')

import os
import shutil
import socket
import tempfile
import unittest

from nss import nss

from pki.client import PKIConnection
from pki.crypto import NSSCryptoProvider


class PKITestCase(unittest.TestCase):
    protocol = 'https'
    hostname = socket.gethostname()
    port = '20443'
    subsystem = 'ca'
    authentication_cert = '/tmp/auth.pem'

    security_domain = u'pki-tests'

    def setUp(self):
        self._connection = None

    @property
    def connection(self):
        if self._connection is not None:
            return self._connection
        self._connection = PKIConnection(
            self.protocol,
            self.hostname,
            self.port,
            self.subsystem,
        )
        if self.authentication_cert:
            self._connection.set_authentication_cert(self.authentication_cert)
        return self._connection


class PKICryptoTestCase(PKITestCase):
    password = b'random password'

    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.mkdtemp()
        cls.dbdir = os.path.join(cls.tempdir, 'nssdb')
        NSSCryptoProvider.setup_database(cls.dbdir, cls.password)
        cls.crypto = NSSCryptoProvider(cls.dbdir, cls.password)
        cls.crypto.initialize()

    @classmethod
    def tearDownClass(cls):
        nss.nss_shutdown()
        shutil.rmtree(cls.tempdir)


if __name__ == '__main__':
    class Main(PKITestCase):
        def test(self):
            print(self.connection.get("/services"))
    unittest.main()
