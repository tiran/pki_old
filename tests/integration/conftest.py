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
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#

import json

import pytest
import betamax
from betamax.serializers import JSONSerializer

from pki.client import PKIConnection


class FilteredSerializer(JSONSerializer):
    """Filter out response fields and pretty print JSON

    Tomcat returns some fields that differ between each request, e.g.
    current date. These headers cause git diffs during recordings.
    """
    name = 'filteredjson'
    drop_response_headers = {'Date', 'ETag', 'Last-Modified'}
    pretty = True

    def serialize(self, cassette_data):
        for interaction in cassette_data['http_interactions']:
            # interaction.pop('recorded_at')
            headers = interaction['response']['headers']
            for drop in self.drop_response_headers:
                headers.pop(drop, None)
        if self.pretty:
            return json.dumps(
                cassette_data,
                sort_keys=True,
                indent=1,
                separators=(',', ': '),
            )
        else:
            return json.dumps(cassette_data, sort_keys=True)


betamax.Betamax.register_serializer(FilteredSerializer)


with betamax.Betamax.configure() as config:
    config.cassette_library_dir = 'tests/integration/cassettes'
    # config.preserve_exact_body_bytes = True
    # 'none, 'all', 'new_episodes'
    # config.default_cassette_options['record_mode'] = 'none'
    config.default_cassette_options['record_mode'] = 'new_episodes'
    # config.default_cassette_options['record_mode'] = 'all'
    config.default_cassette_options['match_requests_on'] = [
        'method', 'uri', 'headers', 'body'
    ]
    config.default_cassette_options['serialize_with'] = 'filteredjson'


class PKIConfig(object):
    remote_protocol = u'https'
    remote_hostname = u'192.168.121.138'
    remote_port = u'8443'
    ca_credentials = ['caadmin', 'Secret123']
    admin_cert = '/tmp/pki-tomcat_admin.pem'

    version = u'10.3.0-0.4.fc23'

    name = u'pki-tests'
    basedn = u'O={}'.format(name)
    subsystems = {u'CA', u'KRA'}
    secure_port = u'8443'
    unsecure_port = u'8080'
    hostname = u'dogtag.example.org'
    ca_name = u'CA {} {}'.format(hostname, secure_port)
    kra_name = u'KRA {} {}'.format(hostname, secure_port)


@pytest.fixture()
def pkicfg():
    return PKIConfig


def get_client(pkicfg, betamax_session, subsystem):
    # enforce fixed user agent.
    # python-requests sets a user agent that contains its version.
    betamax_session.headers['User-Agent'] = 'PKI tests'
    return PKIConnection(
        protocol=pkicfg.remote_protocol,
        hostname=pkicfg.remote_hostname,
        port=pkicfg.remote_port,
        subsystem=subsystem,
        session=betamax_session)


@pytest.fixture()
def ca_connection(pkicfg, betamax_session):
    return get_client(pkicfg, betamax_session, 'ca')
