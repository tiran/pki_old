package com.netscape.certsrv.subca;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.annotations.ClientResponseType;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;

@Path("subca")
public interface SubCAResource {

    @GET
    @Path("{caRef}")
    @ClientResponseType(entityType=CAData.class)
    public Response getCA(@PathParam("caRef") String caRef);

    @POST
    @ClientResponseType(entityType=CAData.class)
    //@ACLMapping("certs")
    //@AuthMethodMapping("certs")
    public Response createCA(CAData data);

}
