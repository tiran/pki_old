package com.netscape.cmstools.subca;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.URI;
import java.util.Locale;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.subca.CAData;
import com.netscape.certsrv.subca.SubCAClient;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class SubCACLI extends CLI {

    public SubCAClient subcaClient;

    public SubCACLI(CLI parent) {
        super("subca", "Sub-CA management commands", parent);

        addModule(new SubCAShowCLI(this));
        addModule(new SubCACreateCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public void execute(String[] args) throws Exception {
        client = parent.getClient();
        subcaClient = new SubCAClient(client, "ca");
        super.execute(args);
    }

    protected static void printCAData(CAData data) {
        System.out.println("  CA handle: " + data.getCARef());
        System.out.println("  Issuer DN: " + data.getDN());
    }

}
