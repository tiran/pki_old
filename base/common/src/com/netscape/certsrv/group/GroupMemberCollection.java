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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.group;

import java.util.ArrayList;
import java.util.Collection;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.jboss.resteasy.plugins.providers.atom.Link;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="GroupMembers")
public class GroupMemberCollection {

    Collection<GroupMemberData> members = new ArrayList<GroupMemberData>();
    Collection<Link> links = new ArrayList<Link>();

    @XmlElement(name="Member")
    public Collection<GroupMemberData> getMembers() {
        return members;
    }

    public void setMembers(Collection<GroupMemberData> members) {
        this.members = members;
    }

    public void addMember(GroupMemberData member) {
        members.add(member);
    }

    @XmlElement(name="Link")
    public Collection<Link> getLinks() {
        return links;
    }

    public void setLink(Collection<Link> links) {
        this.links = links;
    }

    public void addLink(Link link) {
        links.add(link);
    }

    public static void main(String args[]) throws Exception {

        GroupMemberCollection response = new GroupMemberCollection();

        GroupMemberData member1 = new GroupMemberData();
        member1.setID("User 1");
        member1.setGroupID("Group 1");
        response.addMember(member1);

        GroupMemberData member2 = new GroupMemberData();
        member2.setID("User 2");
        member2.setGroupID("Group 1");
        response.addMember(member2);

        JAXBContext context = JAXBContext.newInstance(GroupMemberCollection.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(response, System.out);
    }
}