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
import unittest

from pki.server.deployment.pkiscriptlet import AbstractBasePkiScriptlet
from pki.server.deployment import scriptlets


class PKIDeploymentTests(unittest.TestCase):
    scriptlet_path = os.path.dirname(os.path.abspath(scriptlets.__file__))

    def find_scriptlets(self):
        for filename in os.listdir(self.scriptlet_path):
            if filename.endswith('.py') and not filename == '__init__.py':
                yield filename[:-3]

    def test_scriptlet_imports(self):
        # check if all deployment scriptlets can be imported
        for pki_scriptlet in self.find_scriptlets():
            scriptlet = __import__(
                "pki.server.deployment.scriptlets.%s" % pki_scriptlet,
                fromlist=[pki_scriptlet]
            )
            instance = scriptlet.PkiScriptlet()
            self.assertIsInstance(instance, AbstractBasePkiScriptlet)


if __name__ == '__main__':
    unittest.main()
