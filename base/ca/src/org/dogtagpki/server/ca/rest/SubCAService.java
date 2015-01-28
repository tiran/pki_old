//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2015 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca.rest;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.subca.CAData;
import com.netscape.certsrv.subca.SubCAResource;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author ftweedal
 */
public class SubCAService extends PKIService implements SubCAResource {

    ICertificateAuthority topCA;

    public SubCAService() {
        topCA = (ICertificateAuthority) CMS.getSubsystem("ca");
    }

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    /*
    private final static String LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL =
            "LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL_4";
    private final static String LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE =
            "LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE_3";
    */

    @Override
    public Response getCA(String caRef) {
        ICertificateAuthority ca = null;
        boolean noSuchCA = false;
        try {
          ca = topCA.getSubCA(caRef);
        } catch (EBaseException e) {
            noSuchCA = true;
        }
        if (noSuchCA || ca == null)
            throw new BadRequestException("CA \"" + caRef + "\" does not exist");

        return createOKResponse(readCAData(caRef, ca));
    }

    @Override
    public Response createCA(CAData data) {
        // splice final part off caRef
        String caRef = data.getCARef();

        caRef = StringUtils.strip(caRef, " /");
        String[] components = StringUtils.split(caRef, "/");
        List<String> parentPath = new ArrayList<>();
        for (int i = 0; i < components.length - 1; i++)
            parentPath.add(components[i]);
        String caHandle = components[components.length - 1];

        ICertificateAuthority parentCA = null;
        try {
            parentCA = topCA.getSubCA(parentPath);
        } catch (EBaseException e) {
            throw new BadRequestException("Parent CA \""
                    + StringUtils.join(parentPath, '/')
                    + "\" does not exist");
        }

        ICertificateAuthority subCA = null;
        try {
            subCA = parentCA.createSubCA(caHandle, data.getDN());
        } catch (Exception e) {
            // TODO catch more specific exception
            CMS.debug(e);
            throw new PKIException("Error creating sub-CA: " + e.toString());
        }

        return createOKResponse(readCAData(caRef, subCA));
    }

    private static CAData readCAData(String caRef, ICertificateAuthority ca)
            throws PKIException {
        String dn;
        try {
            dn = ca.getX500Name().toLdapDNString();
        } catch (IOException e) {
            throw new PKIException("Error reading CA data: could not determine Issuer DN");
        }

        return new CAData(caRef, dn);
    }

    /* TODO work out what audit messages are needed
    public void auditProfileChangeState(String profileId, String op, String status) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                auditor.getSubjectID(),
                status,
                profileId,
                op);
        auditor.log(msg);
    }

    public void auditProfileChange(String scope, String type, String id, String status, Map<String, String> params) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(scope, type, id, params));
        auditor.log(msg);
    }
    */

}
