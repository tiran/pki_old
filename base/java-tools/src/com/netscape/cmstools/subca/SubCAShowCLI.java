package com.netscape.cmstools.subca;

import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.subca.CAData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class SubCAShowCLI extends CLI {

    public SubCACLI subcaCLI;

    public SubCAShowCLI(SubCACLI subcaCLI) {
        super("show", "Show sub-CAs", subcaCLI);
        this.subcaCLI = subcaCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <caRef>", options);
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

        if (cmdArgs.length < 1) {
            System.err.println("Error: No caRef specified.");
            printHelp();
            System.exit(-1);
        }

        String caRef = cmdArgs[0];
        CAData data = subcaCLI.subcaClient.getCA(caRef);
        SubCACLI.printCAData(data);
    }

}
