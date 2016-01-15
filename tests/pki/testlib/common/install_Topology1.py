from pki.testlib.common.exceptions import DirSrvException
from pki.testlib.common.mh_wrapper import W_DirSrv
from pki.testlib.common.mh_libdirsrv import DirSrv
from pki.testlib.common.factory import PkiTools
from pki.testlib.common.Qe_class import QeHost
import ConfigParser
import tempfile
import os
import shlex
import time
import socket
import pytest
import constants
import subprocess
from ecdsa.ecdsa import __main__



class PkiInstall(object):
    

    def __init__(self,Host=None, ssl=False):
        
        self.MultiHost = Host
        self.ssl =  ssl
        print "multihost Object methods are:", dir(self.MultiHost)
        if self.MultiHost:
            self.CAHostname = self.MultiHost.hostname
            print "Multihost plugin is used for providing master details."
        else:
            self.CAHostname = socket.gethostname()
            print "Localhost is used.No external master is supplied using yaml file"
        print self.CAHostname
        self.DSInst = W_DirSrv(self.MultiHost,ssl=False)
        print dir(self.DSInst)
        print self.DSInst.DSInstHost
    

    def SetupDS(self,InstName):
            try:
                print self.MultiHost
                ret = self.DSInst.CreateInstance(InstName)
            except DirSrvException:
                print('Could not setup DS Instance')
                raise
            else:
                print('Successfully setup %s DS Instance' %(InstName))
                return ('Success',0)

    def Setup_Config(self):
          
        print("we are here")
        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.CA_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.CA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.CA_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.CA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.CA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_hostname", self.CAHostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_name", constants.CA_SECURITY_DOMAIN_NAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.CA_CLIENT_DIR)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_backup_keys", "True")
        pkiconfig.set("DEFAULT", "pki_backup_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_ds_password",self.DSInst.DSRootDNPwd)
 
        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.CA_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.CA_TOMCAT_PORT)
        pkiconfig.add_section("CA")
        pkiconfig.set("CA", "pki_import_admin_cert", "False")
        pkiconfig.set("CA", "pki_ds_hostname",self.DSInst.DSInstHost)
        (CAcfgfile_fd, CAcfg_file_path) = tempfile.mkstemp(suffix='cfg')
        os.close(CAcfgfile_fd)
        with open(CAcfg_file_path, "wb") as f:
            pkiconfig.write(f) 
        return CAcfg_file_path
             
    def Setup_CAMaster(self,TempFile='/tmp/ca.cfg'):
        print("########CA Block########")
        if isinstance(self.MultiHost, QeHost):
            self.MultiHost.transport.put_file(TempFile , '/tmp/ca.cfg')
            cmd=['pkispawn', '-s', 'CA', '-f', '/tmp/ca.cfg', '-vv']
            print cmd
            print dir(self.MultiHost)
            try:
                self.MultiHost.run_command(cmd,log_stdout=True,raiseonerr=True)
            except Exception as e:
                raise
            else:
                #os.remove(TempFile)
                print("Removed File after successfully from controller machine")
                return True
        else:
            
            print("Test what happen")
            
    def Setup_KRAMaster(self,TempFile='/tmp/ca.cfg'):
        print("########KRA Block########")
        args='sed -i "s/\[CA]/\[KRA]/g" %s' %(TempFile)
        print("Argument used for changing TempFile is : %s",args)
        o=subprocess.Popen(shlex.split(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
        print o
        if isinstance(self.MultiHost, QeHost):
            self.MultiHost.transport.put_file(TempFile , '/tmp/ca.cfg')
            cmd=['pkispawn', '-s', 'KRA', '-f', '/tmp/ca.cfg', '-vv']
            print cmd
            print dir(self.MultiHost)
            try:
                self.MultiHost.run_command(cmd,log_stdout=True,raiseonerr=True)
            except Exception as e:
                raise
            else:
                return True
        else:
            
            print("Test what happen")
            
            
    def Setup_OCSPMaster(self,TempFile='/tmp/ca.cfg'):
        print("########OCSP Block########")
        args='sed -i "s/\[KRA]/\[OCSP]/g" %s' %(TempFile)
        print("Argument used for changing TempFile is : %s",args)
        o=subprocess.Popen(shlex.split(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
        print o
        if isinstance(self.MultiHost, QeHost):
            self.MultiHost.transport.put_file(TempFile , '/tmp/ca.cfg')
            cmd=['pkispawn', '-s', 'OCSP', '-f', '/tmp/ca.cfg', '-vv']
            print cmd
            print dir(self.MultiHost)
            try:
                self.MultiHost.run_command(cmd,log_stdout=True,raiseonerr=True)
            except Exception as e:
                raise
            else:
                return True
        else:
            
            print("Test what happen")
    
    def Setup_TKSMaster(self,TempFile='/tmp/ca.cfg'):
        print("########TKS Block########")
        args='sed -i "s/\[OCSP]/\[TKS]/g" %s' %(TempFile)
        print("Argument used for changing TempFile is : %s",args)
        o=subprocess.Popen(shlex.split(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
        print o
        if isinstance(self.MultiHost, QeHost):
            self.MultiHost.transport.put_file(TempFile , '/tmp/ca.cfg')
            cmd=['pkispawn', '-s', 'TKS', '-f', '/tmp/ca.cfg', '-vv']
            print cmd
            print dir(self.MultiHost)
            try:
                self.MultiHost.run_command(cmd,log_stdout=True,raiseonerr=True)
            except Exception as e:
                raise
            else:
                return True
        else:
            
            print("Test what happen")
            
            
    def Setup_TPSMaster(self,TempFile='/tmp/ca.cfg'):
        print("########TPS Block########")
        args='sed -i "s/\[TKS]/\[TPS]/g" %s' %(TempFile)
        print("Argument used for changing TempFile is : %s",args)
        o=subprocess.Popen(shlex.split(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
        print o
        if isinstance(self.MultiHost, QeHost):
            self.MultiHost.transport.put_file(TempFile , '/tmp/ca.cfg')
            cmd=['pkispawn', '-s', 'TPS', '-f', '/tmp/ca.cfg', '-vv']
            print cmd
            print dir(self.MultiHost)
            try:
                self.MultiHost.run_command(cmd,log_stdout=True,raiseonerr=True)
            except Exception as e:
                raise
            else:
                return True
        else:
            
            print("Test what happen")
    
    def Import_Cert(self):
        self.certdir=constants.CA_CLIENT_DIR
        print("Importing certificate from CAadmin directory")
        args1='pk12util -d %s -i /root/.dogtag/pkitomcat100/test10.p12 -W redhat -k redhat' %(self.profile_dir)



