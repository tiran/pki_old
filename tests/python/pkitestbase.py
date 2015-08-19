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

HERE = os.path.dirname(os.path.abspath(__file__))


class PKITestCase(unittest.TestCase):
    """Base test case for PKI

    The test case provides a connection attribute and skips tests if
    Dogtag PKI is not available.
    """
    protocol = 'https'
    hostname = socket.gethostname()
    port = '20443'
    subsystem = 'ca'
    authentication_cert = os.path.join(HERE, 'admin.pem')
    dogtag_available = None

    security_domain = u'pki-tests'

    @staticmethod
    def check_available(timeout=0.5):
        # set flag on base class
        cls = PKITestCase
        if cls.dogtag_available is not None:
            return cls.dogtag_available
        address = (cls.hostname, cls.port)
        try:
            socket.create_connection(address, timeout=timeout).close()
        except socket.error:
            cls.dogtag_available = False
        else:
            cls.dogtag_available = True
        return cls.dogtag_available

    def setUp(self):
        super(PKITestCase, self).setUp()
        if not self.check_available():
            self.skipTest('Dogtag is not running on %s:%s' %
                          (self.hostname, self.port))
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
    """PKI test case with crypto provider

    The subclass of PKITestCase also provides a temporary NSS database and
    a NSSCryptoProvider.
    """
    password = b'random password'

    @classmethod
    def setUpClass(cls):
        super(PKICryptoTestCase, cls).setUpClass()
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
