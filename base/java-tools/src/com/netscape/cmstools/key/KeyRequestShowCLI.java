// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.key;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmstools.cli.CLI;

public class KeyRequestShowCLI extends CLI {

    public KeyCLI keyCLI;

    public KeyRequestShowCLI(KeyCLI keyCLI) {
        super("request-show", "Get key request", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Request ID>", options);
    }

    public void execute(String[] args) {

        if (args.length != 1) {
            printHelp();
            System.exit(-1);
        }
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);

        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }
        if (cmd.hasOption("help")) {
            printHelp();
            System.exit(1);
        }

        RequestId requestId = new RequestId(args[0].trim());

        KeyRequestInfo keyRequestInfo = keyCLI.keyClient.getRequestInfo(requestId);

        KeyCLI.printKeyRequestInfo(keyRequestInfo);
    }
}
