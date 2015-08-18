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
import sys
import unittest

from pki.server.upgrade import PKIServerUpgrader, PKIServerUpgradeScriptlet


class PKIServerUpgradeTests(unittest.TestCase):
    server_upgrade_dir = os.path.join(sys.prefix, 'share/pki/server/upgrade')

    def test_load_scriptlets(self):
        # test loading of server upgrade scriptlets
        self.assertTrue(os.path.isdir(self.server_upgrade_dir))
        upgrader = PKIServerUpgrader(upgrade_dir=self.server_upgrade_dir)
        versions = upgrader.all_versions()
        self.assertTrue(len(versions))
        for version in versions:
            scriptlets = upgrader.scriptlets(version)
            for scriptlet in scriptlets:
                self.assertIsInstance(scriptlet, PKIServerUpgradeScriptlet)


if __name__ == '__main__':
    unittest.main()
