from pki.testlib.common.exceptions import DirSrvException
from pki.testlib.common.Qe_class import QeHost
from pki.testlib.common.factory import LdapOperations
from os.path import exists
from pki.testlib.common.factory import PkiTools
from ipapython import ipautil
from ipapython import certdb
import os
import ConfigParser
import os.path
import pwd
import array
import ldap
import tempfile
import grp
import subprocess


# Constants
DS_USER = 'nobody'
DS_GROUP = 'nobody'
DS_admin = 'admin'
DS_ROOTDN = 'CN=Directory Manager'


class DirSrv(object):
    """ 
    Setup/Remove Directory Server Instances used by CS subsystems.
    """

    def __init__(self, InstName, InstHost, InstSuffix, RootDNPwd=None, LdapPort=None, TLSPort=None, MultiHost=None):
        """ 
        Initalize DirSrv Object with given Instance_Name, InstHost, suffix, LdapPort, and TLSPort. 

        :param str InstName: Directory Server Instance Name
            :param str InstHost: Host on which Directory server should be setup
            :param str InstSuffix: Suffix required for setup
            :param str RootDNPwd: RootDN Password
            :param str LdapPort: Ldap Port to be used (optional)
            :param int TlsPort: TLSPort to be used for setup (optional)
            :param obj Multihost: Object from pytest multihost plugin (optional)

        """
        self.InstName = InstName
        self.DSInstHost = InstHost
        self.DSInstSuffix = InstSuffix
        self.DSLdapPort = LdapPort
        self.DSTLSPort = TLSPort
        self.DSRootDN = DS_ROOTDN
        self.DSRootDNPwd = RootDNPwd
        self.DSInstName = 'slapd-%s' % InstName
        self.DSRootDir = '/etc/dirsrv'
        self.DSInstPath = os.path.join(self.DSRootDir, self.DSInstName)
        self.MultiHost = MultiHost

    def __str__(self):
        return "%s.%s('%r')" % (self.__module__, self.__class__.__name__, self.__dict__)

    def ___repr__(self):
        return '%s(%s, %r)' % (self.__class__.__name__, self.__dict__)

    def create_config(self):
        """
        Creates the configuration file for setup-ds.pl to create Directory server Instance. 

            :param: None
        :return: File path containing config file.

        """
        config = ConfigParser.RawConfigParser()
        config.optionxform = str
        config.add_section('General')
        config.set('General', 'FullMachineName', self.DSInstHost)
        config.set('General', 'SuiteSpotUserID', DS_USER)
        config.set('General', 'SuiteSpotGroup', DS_GROUP)
        config.set('General', 'ConfigDirectoryAdminID', DS_admin)
        config.add_section('slapd')
        config.set('slapd', 'ServerIdentifier', self.InstName)
        config.set('slapd', 'ServerPort', self.DSLdapPort)
        config.set('slapd', 'Suffix', self.DSInstSuffix)
        config.set('slapd', 'RootDN', self.DSRootDN)
        config.set('slapd', 'RootDNPwd', self.DSRootDNPwd)
        (DScfgfile_fd, DScfg_file_path) = tempfile.mkstemp(suffix='cfg')
        os.close(DScfgfile_fd)
        with open(DScfg_file_path, "wb") as f:
            config.write(f)
        return DScfg_file_path

    def setup_ds(self, DSCfg_file):
        """
        Creates Directory server instance by running setup-ds.pl.
            if MultiHost parameter is passed to DirSrv Object then InstHost parameter contains
        the actual host on which setup-ds.pl is run else setup-ds.pl is run on localhost

            :param str DSCfg_file: Configuration File path 
        :return: True if seutp-ds.pl ran successfully else false 
        :Exceptions: Raises subprocess.CalledProcessError Exception 

            Todo: Should raise an DirSrvException
        """
        if isinstance(self.MultiHost, QeHost):
            self.MultiHost.transport.put_file(DSCfg_file, '/tmp/test.cfg')
            setup_args = ['setup-ds.pl', '--silent',
                          '--file=/tmp/test.cfg', '--debug']
            try:
                output = self.MultiHost.run_command(
                    setup_args, log_stdout=True, raiseonerr=True)
            except subprocess.CalledProcessError as E:
                raise
            else:
                os.remove(DSCfg_file)
                return True
        else:
            setup_args = ['setup-ds.pl', '--silent', '--file=%s' % DSCfg_file]
        try:
            stdin, stdout, return_code = PkiTools.execute(
                setup_args, raiseonerr=True)
        except ipautil.CalledProcessError as e:
            return False
        else:
            os.remove(DSCfg_file)
            return True

    def remove_ds(self, InstName=None):
        """ 
        Removes Directory server Instance 

        :param str InstName: Instance Name
        :return bool: Returns True is successfull else Returns False
        
        Todo: Should raise an DirSrvException
        """
        if InstName is None:
            InstName = self.DSInstName
        remove_args = ['remove-ds.pl', '-i', InstName, '-d']
        if isinstance(self.MultiHost, QeHost):
            try:
                output = self.MultiHost.run_command(
                    remove_args, log_stdout=True, raiseonerr=True)
            except subprocess.CalledProcessError as E:
                return False
            else:
                return True
        else:
            try:
                stdin, stdout, return_code = ipautil.run(
                    remove_args, raiseonerr=True)
            except ipautil.CalledProcessError as e:
                return False
            else:
                return True

    def setup_certs(self, ssl_dir):
        """
        Copies NSS Db files containing CA and Server Certs to all the instance directories. 
        :param str ssl_dir: NSS Directory containing CA and Server-Cert
        :return True if files are are copied, else raises DirSrvException
        """
        #we stop directory server before we copy files , this is required
        #because it's seen that at times, if ns-slapd process is reading
        #the db files, copying of files is successfull but not all data
        #is written causing the files to go corrupt.
        stop_ds = ['systemctl', 'stop', 'dirsrv@%s' % (self.InstName)]
        try:
            self.MultiHost.run_command(stop_ds, log_stdout=True, raiseonerr=True)
        except subprocess.CalledProcessError as E:
            return ("Error", 1)
        else:
            self.MultiHost.log.info('Directory server instance stopped successfully')
        nss_db_files = ['cert8.db', 'key3.db', 'secmod.db', 'pin.txt']
        cacert_file_path = '%s/cacert.pem' % (self.MultiHost.config.test_dir)
        if isinstance(self.MultiHost, QeHost):
            for db_file in nss_db_files:
                source = os.path.join(ssl_dir, db_file)
                destination = os.path.join(self.DSInstPath, db_file)
                print("Source = ", source)
                print("Destination = ", destination)
                self.MultiHost.transport.put_file(source, destination)
            target_pin_file = os.path.join(self.DSInstPath, 'pin.txt')
            change_ownership = ['chown', DS_USER, target_pin_file]
            change_group = ['chgrp', DS_GROUP, target_pin_file]
            chmod_file = ['chmod', '600', target_pin_file]
            # copy the cacert file to test_dir
            self.MultiHost.transport.put_file(os.path.join(
                ssl_dir, 'cacert.pem'), cacert_file_path)
            try:
                output = self.MultiHost.run_command(
                    change_ownership, log_stdout=True, raiseonerr=True)
            except subprocess.CalledProcessError as E:
                raise DirSrvException(
                    'Could not change ownerhsip of pin.txt file')
            try:
                output = self.MultiHost.run_command(
                    change_group, log_stdout=True, raiseonerr=True)
            except subprocess.CalledProcessError as E:
                raise DirSrvException(
                    'Could not change group ownerhsip of pin.txt file')
            try:
                output = self.MultiHost.run_command(
                    chmod_file, log_stdout=True, raiseonerr=True)
            except subprocess.CalledProcessError as E:
                raise DirSrvException(
                    'Could not change permissions of pin.txt file')
            start_ds = ['systemctl', 'start', 'dirsrv@%s' % (self.InstName)]
            try:
                self.MultiHost.run_command(start_ds, log_stdout=True, raiseonerr=True)
            except subprocess.CalledProcessError as E:
                return ("Error", 1)
            else:
                self.MultiHost.log.info('Directory server instance started successfully')
                return True


    def enable_ssl(self, binduri, tls_port):
        """
        Sets TLS Port and Enabled SSL on Directory Server
        :param str binduri: ldap uri to bind with
        :param str binddn: DN required to bind
        :param str tls_port: TLS port to be set 

        :Retruns True if successful else raises LdapException
        """

        l = LdapOperations(uri=binduri, binddn=self.DSRootDN,
                           bindpw=self.DSRootDNPwd)
        # Enable TLS
        mod_dn1 = 'cn=encryption,cn=config'
        add_tls = [(ldap.MOD_ADD, 'nsTLS1', 'on')]
        (ret, return_value) = l.modify_ldap(mod_dn1, add_tls)
        if not return_value:
            raise LdapException('Could not enable TLS, Error:%s' % (ret))
        else:
            print('Enabled nsTLS1=on')
        # Add the server-cert nick
        entry1 = {
            'objectClass': ['top', 'nsEncryptionModule'],
            'cn': 'RSA',
            'nsSSLtoken': 'internal (software)',
            'nsSSLPersonalitySSL': 'Server-Cert-%s' % (self.DSInstHost),
            'nsSSLActivation': 'on'
        }
        dn1 = 'cn=RSA,cn=encryption,cn=config'

        (ret, return_value) = l.add_entry(entry1, dn1)
        if not return_value:
            raise LdapException('Could not set Server-Cert nick:%s' % (ret))
        else:
            print('Enabled Server-Cert nick')

        # Enable security
        mod_dn2 = 'cn=config'
        enable_security = [(ldap.MOD_REPLACE, 'nsslapd-security', 'on')]
        (ret, return_value) = l.modify_ldap(mod_dn2, enable_security)
        if not return_value:
            raise LdapException(
                'Could not enable nsslapd-security, Error:%s' % (ret))
        else:
            print('Enabled nsslapd-security')

        # set the appropriate TLS port
        mod_dn3 = 'cn=config'
        enable_ssl_port = [
            (ldap.MOD_REPLACE, 'nsslapd-securePort', str(tls_port))]
        (ret, return_value) = l.modify_ldap(mod_dn3, enable_ssl_port)
        print("Return value = ", ret)
        if not return_value:
            raise LdapException(
                'Could not set nsslapd-securePort, Error:%s' % (ret))
        else:
            print('Enabled nsslapd-securePort=%r' % tls_port)
        return True
