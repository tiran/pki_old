#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This module implements generic functions for py.test framework.
"""
import subprocess
import os
import ldap
import tempfile
import array
import random
import collections
from os.path import exists
from ldap import modlist
from ipapython import certdb
from lxml import etree
from .exceptions import PkiLibException


class PkiTools(object):
    '''
        PkiTools consists of functions related to creation of
        certificate requests, updating profile xml with certificate
        requests.
    '''

    def __init__(self, nssdir=None, nssdir_pwd=None):

        if nssdir is None:
            self.nssdb = tempfile.mkdtemp('nssdir')
        else:
            self.nssdb = nssdir
        if nssdir_pwd is None:
            self.nssdb_pwd = 'Secret123'
        else:
            self.nssdb_pwd = nssdir_pwd

    def create_nssdb(self):
        '''
        Create a NSS Database on a temporary Directory
        :return str nssdb: path of the NSS DB Directory
        '''
        self.pwdFileName = 'pwfile'
        self.noiseFileName = 'noiseFile'
        self.pwdFilePath = os.path.join(self.nssdb, self.pwdFileName)
        self.noise = array.array('B', os.urandom(128))
        self.noiseFilePath = os.path.join(self.nssdb, self.noiseFileName)
        with open(self.pwdFilePath, 'w') as f:
            f.write(self.nssdb_pwd)
        CertDBObj = certdb.NSSDatabase(nssdir=self.nssdb)
        CertDBObj.create_db(self.pwdFilePath)
        nss_db_files = ['cert8.db', 'key3.db', 'secmod.db', 'pwfile']
        for db_file in nss_db_files:
            if not exists(os.path.join(self.nssdb, db_file)):
                raise PkiLibException('Could not setup NSS DB on %s' % self.nssdb)
        return self.nssdb

    def strip_header(self, csr):
        '''
        Strip headers from certificate request
        :param str csr: Certificate request with headers
        :return str stripped_csr: Certificate request with stripped headers
        '''

        headerlen = 40
        s = csr.find("-----BEGIN NEW CERTIFICATE REQUEST-----")
        if s == -1:
            headerlen = 36
            s = csr.find("-----BEGIN CERTIFICATE REQUEST-----")
        if s >= 0:
            e = csr.find("-----END")
            stripped_csr = csr[s + headerlen:e]
        return stripped_csr

    def generate_pkcs10(self, nssdb_dir, nssdb_pwd, subject_dn, output_file, keysize='2048', keyalgo='rsa'):
        '''
        Generate certificate request of type pkcs10.

        :param str nssdb_dir: Directory containing NSS Db
        :param str nssdb_pwd: NSS DB password
        :param str subject_dn: subject DN for which the certificate
            request should be generated
        :param str output_file: path of the output file where certificate request
            should be stored
        :param str keysize: size of the rsa keys (default 2048)
        :param str keyalgo: Algorithm to be used to generate key pair (default 'rsa')

        :return str csr: Certificate request stripped with headers
        '''

        if nssdb_dir is None:
            nssdb_dir = self.nssdb
        if nssdb_pwd is None:
            nssdb_pwd = self.nssdb_pwd
        args = ['PKCS10Client',
                "-p", nssdb_pwd,
                "-d", nssdb_dir,
                "-a", keyalgo,
                "-l", keysize,
                "-o", output_file,
                "-n", subject_dn]
        try:
            stdout, stderr, returncode = self.execute(args)
        except subprocess.CalledProcessError as Err:
            return (Err.returncode, args, stdout)
        else:
            with open(output_file, "r") as fp:
                pkcs10_cert_request = fp.readlines()
            pkcs10_csr = "".join(pkcs10_cert_request)
            stripped_request = self.strip_header(pkcs10_csr)
            csr = ''.join(stripped_request.split())
            return csr

    def generate_subject_dn(self, inputs):
        '''
        Generate Subject DN based on the inputs provided
        :param dict inputs: Dictionary containing inputs to create a subject DN
            {CN:'Server1.example.org', 'E':'root@localhost', 'OU':'IDM QE',Country:'US'}
        :return str subject: returns subject in x.500 DN format
        '''
        ordered_dn = collections.OrderedDict(sorted(inputs.items(), key=lambda t: t[0]))
        subject = (','.join('{0}={1}'.format(k, v) for (k, v) in ordered_dn.items()))
        return subject

    def update_profile_xml(self, csr, profile_xml, request_type='pkcs10'):
        '''
        Modify profile xml file with certificate request
        :param str csr: Stripped Certificate request
        :param str profile_xml: path of the profile xml
        :param str request_type: certificate request type (default:'pkcs10')
        :return None
        :raises PkiLibException: if unable to update profile xml
        '''

        parser = etree.XMLParser(encoding="utf-8")
        tree = etree.parse(profile_xml, parser=parser)
        cert_request_type = tree.xpath('./Input[@id="i1"]/Attribute[@name="cert_request_type"]')
        cert_request_type[0][0].text = request_type
        cert_request = tree.xpath('./Input[@id="i1"]/Attribute[@name="cert_request"]')
        cert_request[0][0].text = csr
        try:
            tree.write(profile_xml)
        except:
            raise PkiLibException('Could not fill the xml file with appropriate values')

    def execute(self, args, stdin=None, capture_output=True, raiseonerr=False, env=None, cwd=None):
        """
        Execute a command and return stdout, stderr and return code

        :param str args: List of arguments for the command
        :param str stdin: Optional input
        :param bool capture_output: Capture output of the command (default True)
        :param bool raiseonerr: Raise exception if command fails
        :param str env: Environment variables to be set before the command is run
        :param str cwd: Current working Directory

        :return stdout, stderr and returncode: if command return code is 0 else raises exception if raiseonerr is True
        """
        p_in = None
        p_out = None
        p_err = None
        if env is None:
            env = os.environ.copy()
        if capture_output:
            p_out = subprocess.PIPE
            p_err = subprocess.PIPE
        try:
            proc = subprocess.Popen(args, stdin=p_in, stdout=p_out, stderr=p_err,
                                    close_fds=True, env=env, cwd=cwd)
            stdout, stderr = proc.communicate(stdin)
        except KeyboardInterrupt:
            proc.wait()
            raise
        if proc.returncode != 0 and raiseonerr:
            raise subprocess.CalledProcessError(proc.returncode, args, stdout)
        else:
            return (stdout, stderr, proc.returncode)

    @classmethod
    def createselfsignedcerts(cls, serverlist, ca_dn=None, passphrase='Secret123', canickname='Example CA'):
        """
        Creates a NSS DB in /tmp/nssDirxxxx where self signed Root CA and Server Certs
        are created

        :param str CA_DN: Distinguished Name for CA Cert
        :param str Server_DN: Distinguished Name for Server Cert
        """
        if ca_dn is None:
            ca_dn = 'CN=Example CA,O=Example,L=Raleigh,C=US'
        NSSPassPhrase = passphrase
        noise = array.array('B', os.urandom(128))
        pwdFileName = 'pwfile'
        noiseFileName = 'noiseFile'
        pinFileName = 'pin.txt'
        nss_dir = tempfile.mkdtemp('nssdir')
        pwdFilePath = os.path.join(nss_dir, pwdFileName)
        CertDBObj = certdb.NSSDatabase(nssdir=nss_dir)
        # setup NSS DB with the password created
        CertDBObj.create_db(pwdFilePath)
        noiseFilePath = os.path.join(nss_dir, noiseFileName)
        pinFilePath = os.path.join(nss_dir, pinFileName)

        CACertPath = os.path.join(nss_dir, 'cacert.der')
        CAPemPath = os.path.join(nss_dir, 'cacert.pem')
        ServerPemPath = os.path.join(nss_dir, 'server.pem')

        with open(pwdFilePath, 'w') as f:
            f.write(NSSPassPhrase)
        with open(noiseFilePath, 'w') as f:
            f.write(str(noise))

        ca_args = ["-f", pwdFilePath,
                   "-S",
                   "-n", canickname,
                   "-s", ca_dn,
                   "-t", "CT,,",
                   "-x",
                   "-z", noiseFilePath]

        ca_pem = ["-f", pwdFilePath,
                  "-L",
                  "-n", canickname,
                  "-a",
                  "-o", CAPemPath]

        with open(pinFilePath, 'w') as f:
            f.write('Internal (Software) Token:%s' % NSSPassPhrase)
        # since there is no exception handling , we need to verify
        # if the nssdb is created properly, we check if cert8.db,
        # secmod.db and key3.db exists
        nss_db_files = ['cert8.db', 'key3.db', 'secmod.db', 'pin.txt']
        for db_file in nss_db_files:
            if not exists(os.path.join(nss_dir, db_file)):
                raise PkiLibException('Could not setup NSS DB on %s' % nss_dir)

        stdin, stdout, return_code = CertDBObj.run_certutil(ca_args)
        if return_code != 0:
            raise PkiLibException('Could not create Self signed CA Cert')
        else:
            CertDBObj.export_pem_cert(canickname, CACertPath)

        for server in serverlist:
            Server_DN = 'CN=%s' % (server)
            ServerNickName = 'Server-Cert-%s' % (server)
            serverCertPath = os.path.join(nss_dir, '%s.der' % (ServerNickName))
            server_pem = ["-f", pwdFilePath,
                          "-L",
                          "-n", ServerNickName,
                          "-a",
                          "-o", ServerPemPath]
            server_args = ["-f", pwdFilePath,
                           "-S",
                           "-n", ServerNickName,
                           "-s", Server_DN,
                           "-c", canickname,
                           "-t", "u,u,u",
                           "-v", "720",
                           "-m", str(random.randint(1000, 2000)),
                           "-z", noiseFilePath]
            stdin, stdout, return_code = CertDBObj.run_certutil(server_args)
            if return_code != 0:
                raise PkiLibException('Could not create Server-Cert')
            else:
                CertDBObj.export_pem_cert(ServerNickName, serverCertPath)
                stdin, stdout, return_code = CertDBObj.run_certutil(server_pem)
                if return_code != 0:
                    raise PkiLibException('Could not create Server pem file')

        stdin, stdout, return_code = CertDBObj.run_certutil(ca_pem)
        if return_code != 0:
            raise PkiLibException('Could not create CA pem file')
        else:
            return nss_dir


class LdapOperations(object):
    '''
        LDapOperations consists of functions related to ldap operations, like
        adding entry, adding a DN, modifying DN, etc. These functions are primarily
        used to enable/disable SSL
    '''

    def __init__(self, uri, binddn, bindpw):
        self.uri = uri
        self.binddn = binddn
        self.bindpw = bindpw
        self.conn = ldap.initialize(uri)
        self.conn = self.bind()

    def bind(self):
        try:
            self.conn.simple_bind_s(self.binddn, self.bindpw)
        except ldap.SERVER_DOWN as err:
            return self._parseException(err)
        except ldap.INVALID_CREDENTIALS as err:
            return self._parseException(err)
        else:
            return self.conn

    def add_entry(self, entry, dn):
        ldif = modlist.addModlist(entry)
        try:
            self.conn.add_s(dn, ldif)
        except:
            raise
        else:
            return ('Success', True)

    def _parseException(self, err):
        error_message = err.message['desc']
        return_value = False
        return (error_message, return_value)

    def modify_ldap(self, dn, modify_list):
        try:
            self.conn.modify_s(dn, modify_list)
        except ldap.NO_SUCH_ATTRIBUTE:
            return False
        except ldap.NO_SUCH_OBJECT as err:
            return self._parseException(err)
        except ldap.OBJECT_CLASS_VIOLATION as err:
            return self._parseException(err)
        except ldap.TYPE_OR_VALUE_EXISTS as err:
            return self._parseException(err)
        except ldap.UNWILLING_TO_PERFORM:
            return self._parseException(err)
        else:
            return ('Success', True)
