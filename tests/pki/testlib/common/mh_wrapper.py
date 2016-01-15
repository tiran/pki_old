from pki.testlib.common.exceptions import DirSrvException
from pki.testlib.common.exceptions import PkiLibException
from pki.testlib.common.exceptions import LdapException
from pki.testlib.common.factory import PkiTools
from pki.testlib.common.Qe_class import QeHost
from pki.testlib.common.mh_libdirsrv import DirSrv
from os.path import exists
import os.path
import subprocess
import socket
import time


class W_DirSrv(object):
    """ 
    This is a wrapper class for DirSrv object which validates all the inputs sent to DirSrv object.
    Selects Ldap and SSL Ports sanely, Validates the inputs and in cases uses certain default values in 
    cases not all options are provided.

    Defaults:

    **DSInstHost: localhost**

    **DSRootDN:` Secret123**

    **DSInstSuffix:` 'dc=example,dc=org**

    **Ldap and TLS ports are choosen from the available list of below ports:**

    **DSPorts: [30389, 31389, 32389, 33389, 34389, 35389, 36389, 37389, 38389, 39389]** 

    **TLSPorts:  [30636, 31636, 32636, 33636, 34636, 35636, 36636, 37636, 38636, 39636]**

    """

    def __init__(self, Host=None, ssl=None, ssldb=None):
        """
        Create a DirSrv object for a specific Host. Specify the ports, Instance details to the Dirsrv object 

        :param str Host: Host Object of pytest multihost
        :param str ssl: Enable ssl if ssl is True to DS Instance
        """

        self.DSUsedPorts = {}
        self.DirSrvInfo = {}
        self.DirSrvInst = None
        self.DSInstName = None
        self.Host = Host
        if self.Host is None:
            self.DSInstHost = socket.gethostname()
        else:
            self.DSInstHost = self.Host.hostname
        #self.PassPhrase = 'Secret123'
        #self.CA_DN = 'CN=Example CA,O=Example,L=Raleigh,C=US'
        #self.CANickName = 'Example CA'
        #self.ServerNickName = 'Server-Cert'
        self.ssl = ssl
        if self.ssl:
            self.sslDir = ssldb

    def _set_options(self):
        """
        Set default values:
            Defaults:
        DSInstHost: localhost
            DSRootDN: Secret123
        DSInstSuffix: 'dc=example,dc=org'
            Ldap and TLS ports are choosen from the available list of below ports:
        DSPorts = [1389, 2389, 3389, 4389, 30389, 31389, 32389, 33389, 34389, 35389, 36389, 37389, 38389, 39389
            TLSPorts = [1636, 2636, 3636, 4636, 30636, 31636, 32636, 33636, 34636, 35636, 36636, 37636, 38636, 39636]
        """
        if self.DSRootDNPwd is None:
            self.DSRootDNPwd = 'Secret123'

        if self.DSInstSuffix is None:
            self.DSInstSuffix = "dc=example,dc=org"
        # Get ports
        try:
            self.DSLdapPort, self.DSTLSPort = self._set_ports(
                self.DSLdapPort, self.DSTLSPort)
        except IndexError as err:
            return ("No More ports available", 1)
        else:
            self.DSUsedPorts[self.DSInstName] = [
                self.DSLdapPort, self.DSTLSPort]
        # validate Instance
        try:
            self._validate_options()
        except DirSrvException as err:
            return err.msg, err.rval
        else:
            return ("Success", 0)

    def _set_ports(self, u_port, e_port):
        """
        Idea behind this is when a directory server instance needs
        to be created we need ports for ldap and ssl ports.
        1. check if LdapPort and SSLPort is given
            1.1 If given, verify if the ports are available(not used)
                1.1.1. Bind that port to ldap_port_t using semanage command
                1.1.2. Use the ports and add it to the self.UsedPorts list
            1.2 else raise exception
        2. If LdapPort and SSLPort is not given.
            2.1 Check if the ports are available(not used)
            2.1.1. Bind the port to ldap_port_t using semanage command
            2.1.2. Use the ports and add it to self.UsedPorts list
        """
        DSPorts = [1389, 2389, 4389, 30389, 31389, 32389,
                   33389, 34389, 35389, 36389, 37389, 38389, 39389]
        TLSPorts = [1636, 2636, 4636, 30636, 31636, 32636,
                    33636, 34636, 35636, 36636, 37636, 38636, 39636]

        if u_port is None and e_port is None:
            for ldap_port, ldaps_port in zip(DSPorts, TLSPorts):
                if (self._check_remote_port(ldap_port) or self._check_remote_port(ldaps_port)):
                    pass
                else:
                    return ldap_port, ldaps_port
        else:
            a = []
            for ports in self.DSUsedPorts.values():
                a.append(ports)

            b = []
            for l_port, s_port in zip(DSPorts, TLSPorts):
                b.append((l_port, s_port))

            if (len(set(a)) > len(set(b))):
                available_ports = set(a) - set(b)
            else:
                available_ports = set(b) - set(a)
            print("available_ports =", available_ports)
            sorted_available_ports = sorted(available_ports)
            return sorted_available_ports[0]

    def _check_remote_port(self, port):
        """
            checks if the port on the remote host is free

        :param: int port: 

            :return bool: True if port is free else return False if port is unavailable
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            result = s.connect((self.DSInstHost, port))
        except socket.error as e:
            print("Unable to connect to port %s due to error %r" %
                  (port, e.errno))
            return False
        s.close()
        if result != 0:
            return True
        else:
            return False

    def _validate_options(self):
        """
        Verifies if the instance directory alread exists 
        :param: None
        :return: raises DirSrvException if the instance directory already exists else retuns True
        """
        if isinstance(self.Host, QeHost):
            check_instance = ['ls ' '/etc/dirsrv/slapd-%s' % self.DSInstName]
            try:
                output = self.Host.run_command(
                    check_instance, log_stdout=True, raiseonerr=True)
            except subprocess.CalledProcessError as E:
                return True
            else:
                raise DirSrvException(
                    '%s Instance already Exists' % self.DSInstName)
        else:
            if exists(os.path.join('/etc/dirsrv/', 'slapd-%s' % self.DSInstName)):
                raise DirSrvException(
                    '%s Instance already Exists' % self.DSInstName)
            else:
                return True

    def create_ds_instance(self, InstName, InstSuffix=None, RootDNPwd=None, LdapPort=None, TLSPort=None):
        """
        Creates Directory server instances

        :param str InstName: Instance Name
        :param str InstHost: Host on which instance should be created
        :param str InstSuffix: Suffix to be created
        :param str RootDNPwd: Root DN password
        :param str LdapPort: Ldap Port to be used
        :param str TLSPort: TLSPort port to be used

        :return str result, return_code: output of the command and return code
        :raises DirSrvException: if Directory server instance could not be created
        """
        self.DSInstName = InstName
        self.DSInstSuffix = None
        self.DSRootDNPwd = RootDNPwd
        self.DSLdapPort = LdapPort
        self.DSTLSPort = TLSPort

        result, return_code = self._set_options()
        if return_code == 0:
            self.DirSrvInst = DirSrv(self.DSInstName, self.DSInstHost,
                                     self.DSInstSuffix, self.DSRootDNPwd, self.DSLdapPort,
                                     self.DSTLSPort, self.Host)
            cfg_file = self.DirSrvInst.create_config()
            result = self.DirSrvInst.setup_ds(cfg_file)
            self.DirSrvInfo[self.DSInstName] = self.DirSrvInst.__dict__
            if self.ssl:
                try:
                    ret = self.DirSrvInst.setup_certs(self.sslDir)
                except DirSrvException as err:
                    return err.msg, err.rval
                else:
                    (result, return_code) = self.enablessl()
            return result, return_code
        else:
            raise DirSrvException('Could not setup Directory Server Instance')

    def enablessl(self):
        """
        Enable SSL/TLS on Instance, by adding TLS Port to ldap_port_t , Enable TLS and
        restart Directorry Server Instance

        :param: None

        :returns tuple:('Success', 0) for success else return ('Error', 1)
        """
        # add tls port to ldap_port_t label
        add_tls_port = ['semanage', 'port', '-a', '-t',
                        'ldap_port_t', '-p', 'tcp', str(self.DSTLSPort)]
        restart_ds = ['systemctl', 'restart', 'dirsrv@%s' % (self.DSInstName)]
        if isinstance(self.Host, QeHost):
            try:
                output = self.Host.run_command(
                    add_tls_port, log_stdout=True, raiseonerr=True)
            except subprocess.CalledProcessError as E:
                return ("Error", 1)
            else:
                self.Host.log.info(
                    'Added %s port to ldap_port_t' % (self.DSTLSPort))
            try:
                output = self.DirSrvInst.enable_ssl(
                    'ldap://%s:%r' % (self.DSInstHost, self.DSLdapPort), self.DSTLSPort)
            except LdapException as err:
                return ("Error", 1)
            else:
                try:
                    self.Host.run_command(
                        restart_ds, log_stdout=True, raiseonerr=True)
                except subprocess.CalledProcessError as E:
                    return ("Error", 1)
                else:
                    self.Host.log.info(
                        'Directory server instance restarted successfully')
                    # sleep for 10 seconds
                    time.sleep(10)
                tail_cmd = ['tail', '-n', '100', '/var/log/dirsrv/slapd-%s/errors'%(self.DSInstName)]
                try:
                    self.Host.run_command(tail_cmd, log_stdout = True, raiseonerr = True)
                except subprocess.CalledProcessError as E:
                    return ("Error", 1)
                else:
                    return ("Success", 0)
        else:
            try:
                stdout, stderr, process_ret = PkiTools.execute(add_tls_port)
            except subprocess.CalledProcessError:
                return ("Error", 1)
            else:
                if process_ret != 0:
                    return stderr, process_ret
                try:
                    output = self.DirSrvInst.enable_ssl(
                        'ldap://%s:%r' % (self.DSInstHost, self.DSLdapPort), tls_port)
                except LdapException as err:
                    return (err.msg, err, rval)
                else:
                    # restart Directory server
                    try:
                        stdout, stderr, process_ret = PkiTools.execute(
                            restart_ds)
                    except subprocess.CalledProcessError:
                        return ("Error", 1)
                    else:
                        if process_ret == 1:
                            return (stdout, 0)
                        elif process_ret != 0:
                            return (stderr, process_ret)
                        else:
                            return (stdout, process_ret)

    def remove_ds_instance(self, InstName):
        """
        Removes Directory server instance

        :param str InstName:

        :return bool: Returns True

        :raises DirSrvException: if Directory Server instance cannot be removed
        """
        ret = self.DirSrvInfo[InstName]
        if ret['InstName'] == InstName:
            DSInstName = ret['DSInstName']
            result = self.DirSrvInst.remove_ds(DSInstName)
            if result:
                del self.DSUsedPorts[InstName]
                return True
            else:
                raise DirSrvException(
                    'Could not remove Directory Server Instance', DSInstName)
        else:
            raise DirSrvException(
                "%s Instance could not be found" % (InstName))
