#!/usr/bin/python
"""Set up test instances of 389 dirsrv and Dogtag PKI.
"""
from __future__ import print_function

import os
import socket
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKI_INSTANCE_NAME = 'pki-tomcat-tests'
PKI_INSTANCE_PATH = '/etc/pki/{}'.format(PKI_INSTANCE_NAME)
PKI_SUBSYSTEMS = ['CA', 'KRA']
DIRSRV_INSTANCE_NAME = 'slapd-{}'.format(PKI_INSTANCE_NAME)
DIRSRV_INSTANCE_PATH = '/etc/dirsrv/{}'.format(DIRSRV_INSTANCE_NAME)
PKI_CFG = os.path.join(HERE, 'pki.cfg')

PORT_BASE = 20000
CONFIG = {
    'pki_instance_name': PKI_INSTANCE_NAME,
    'ldap_port': PORT_BASE + 389,
    'http_port': PORT_BASE + 80,
    'https_port': PORT_BASE + 443,
    'password': 'Secret123',
    'security_domain': 'pki-tests',
    'suffix': 'dc=example,dc=com',
    'domain': 'example.com',
    'hostname': socket.gethostname(),
}


def check_call(cmd):
    print(' '.join(cmd))
    return subprocess.check_call(cmd)


def create_config():
    with open(PKI_CFG + '.template') as f:
        template = f.read()
    config = template % CONFIG
    with open(PKI_CFG, 'w') as f:
        f.write(config)


def pkidestroy(subsystem):
    path = os.path.join(PKI_INSTANCE_PATH, subsystem.lower())
    if os.path.isdir(path):
        cmd = ['pkidestroy', '-i', PKI_INSTANCE_NAME, '-s', subsystem.upper()]
        check_call(cmd)
        return True
    else:
        return False


def pkispawn(subsystem):
    cmd = ['pkispawn', '-v', '-f', PKI_CFG, '-s', subsystem]
    check_call(cmd)


def remove_ds():
    if os.path.isdir(DIRSRV_INSTANCE_PATH):
        cmd = ['remove-ds.pl', '-f', '-i', DIRSRV_INSTANCE_NAME]
        check_call(cmd)
        return True
    else:
        return False


def setup_ds():
    cmd = [
        'setup-ds.pl',
        '--silent',
        'General.FullMachineName={hostname}'.format(**CONFIG),
        'General.SuiteSpotUserID=nobody',
        'General.SuiteSpotGroup=nobody',
        'slapd.ServerPort={ldap_port}'.format(**CONFIG),
        'slapd.ServerIdentifier={pki_instance_name}'.format(**CONFIG),
        'slapd.Suffix={suffix}'.format(**CONFIG),
        'slapd.RootDN=cn=Directory Manager',
        'slapd.RootDNPwd={password}'.format(**CONFIG),
    ]
    check_call(cmd)


def dump_admin_cert():
    cert = os.path.join(HERE, 'admin.pem')
    cmd = [
        'openssl',
        'pkcs12',
        '-in',
        '/root/.dogtag/{pki_instance_name}/ca_admin_cert.p12'.format(**CONFIG),
        '-out',
        cert,
        '-nodes',
        '-passin',
        'pass:{password}'.format(**CONFIG)
    ]
    check_call(cmd)


def main():
    create_config()

    for subsystem in reversed(PKI_SUBSYSTEMS):
        pkidestroy(subsystem)
    remove_ds()

    setup_ds()
    for subsystem in PKI_SUBSYSTEMS:
        pkispawn(subsystem)
        # give it some time to settle
        time.sleep(2)

    dump_admin_cert()


if __name__ == '__main__':
    main()
