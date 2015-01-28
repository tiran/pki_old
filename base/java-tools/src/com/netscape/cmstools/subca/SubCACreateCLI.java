package com.netscape.cmstools.subca;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.subca.CAData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class SubCACreateCLI extends CLI {

    public SubCACLI subcaCLI;

    public SubCACreateCLI(SubCACLI subcaCLI) {
        super("create", "Create sub-CAs", subcaCLI);
        this.subcaCLI = subcaCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <handle> <dn>", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        String[] positionalArgNames = {
            "CA handle",
            "Issuer DN"
        };

        if (cmdArgs.length < positionalArgNames.length) {
            System.err.println("Error: No "
                    + positionalArgNames[cmdArgs.length]
                    + " specified.");
            printHelp();
            System.exit(-1);
        }

        String caRef = cmdArgs[0];
        String dn = cmdArgs[1];
        CAData data = new CAData(caRef, dn);
        CAData newData = subcaCLI.subcaClient.createCA(data);
        SubCACLI.printCAData(newData);
    }

}
