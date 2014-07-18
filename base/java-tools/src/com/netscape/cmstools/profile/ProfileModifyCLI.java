package com.netscape.cmstools.profile;

import java.io.FileNotFoundException;
import java.util.Arrays;

import javax.xml.bind.JAXBException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.profile.ProfileData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileModifyCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileModifyCLI(ProfileCLI profileCLI) {
        super("mod", "Modify profiles", profileCLI);
        this.profileCLI = profileCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <file> [OPTIONS...]", options);
    }

    public void execute(String[] args) {
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
            System.err.println("Error: No filename specified.");
            printHelp();
            System.exit(-1);
        }

        String filename = cmdArgs[0];
        if (filename == null || filename.trim().length() == 0) {
            System.err.println("Error: Missing input file name.");
            printHelp();
            System.exit(-1);
        }

        try {
            ProfileData data = ProfileCLI.readProfileFromFile(filename);
            data = profileCLI.profileClient.modifyProfile(data);

            MainCLI.printMessage("Modified profile " + data.getId());

            ProfileCLI.printProfile(data, profileCLI.getClient().getConfig().getServerURI());

        } catch (FileNotFoundException | JAXBException  e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(-1);
        }
    }
}