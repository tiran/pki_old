from .exceptions import PkiLibException
from subprocess import CalledProcessError
from .factory import PkiTools
import re
""" This file contains methods to create role users,
cert request submit, cert approval for CA subsystem """


class CertSetup(object):
    """
    This class contains methods to create Role Users, Submit
    request and approve requests.
    """

    def __init__(self, host, client_dir, client_dir_pwd, ca_admin_nick,
                 subsystem, http_port, nssdb_dir=None, nssdb_pwd=None):
        self.client_dir = client_dir
        self.client_dir_pwd = client_dir_pwd
        self.sys_admin_nick = ca_admin_nick
        self.multihost = host
        self.sys_http_port = http_port
        self.subsystem = subsystem
        if nssdb_dir is None:
            self.nssdb_dir = "%s/%s" % (self.multihost.config.test_dir, 'certdb')
        else:
            self.nssdb_dir = nssdb_dir
        if nssdb_pwd is None:
            self.nssdb_pwd = 'Secret123'
        else:
            self.nssdb_pwd = nssdb_pwd
        self.ca_admin_p12_path = "%s/%s" % (self.client_dir, 'ca_admin_cert.p12')

    def create_certdb(self):
        ''' Creates Certificate Database
        raise PkiLibException if security database already exists
        '''
        output = self.multihost.run_command(['pki', '-d', self.nssdb_dir,
                                             '-c', self.nssdb_pwd, 'client-init'], raiseonerr=False)
        if 'Security database already exists' in output.stdout_text and output.returncode is 255:
            raise PkiLibException('Security Database already Exists', '255')

    def import_ca_admin_p12(self):
        ''' Import CA Admin's p12 file to certdb
        raise PkiLibException if unable to import CA Admin p12 file
        '''
        try:
            self.multihost.run_command(['pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                                        'client-cert-import', 'caadmin', '--pkcs12', self.ca_admin_p12_path,
                                        '--pkcs12-password', self.client_dir_pwd])
        except CalledProcessError as E:
            raise PkiLibException('Unable to import CA Admin p12', E.returncode)
        else:
            self.multihost.log.info(
                "Successfully import CA Admin p12 file to nssdb %s" % (self.nssdb_dir))

    def import_ca_cert(self):
        ''' Import CA Cert to certdb '''
        try:
            self.multihost.run_command(['pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                                        '-h', self.multihost.hostname, '-p', self.sys_http_port,
                                        'client-cert-import', 'CA', '--ca-server'])
        except CalledProcessError as E:
            raise PkiLibException('Unable to import CA cert', E.returncode)
        else:
            self.multihost.log.info("Successfully import ca cert to nssdb %s" % (self.nssdb_dir))

    def create_role_user(self, user_nick, subsystem, userid, groupid):
        ''' create role user for specific subsystem
        :param str user_nick: Nickname of the user using which role user should be added
            if None, it uses Admin cert
        :param str subsystem: Subsystem to which user should be added
        :param str userid: User id to be added
        :param str groupid: Group to which the userid should be member of
        :Returns None
        :raises PkiLibException if adding the user or making the user member of
            of the group fails
        '''
        if user_nick is None:
            user_nick = self.sys_admin_nick,
        try:
            self.multihost.run_command(['pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                                        '-h', self.multihost.hostname, '-p', self.sys_http_port,
                                        '-n', user_nick, self.subsystem, 'user-add',
                                        userid, '--fulName', userid])
        except CalledProcessError as E:
            raise PkiLibException('Unable to create user cert', E.returncode)
        else:
            self.multihost.log.info("Successfully created user %s" % (userid))
        try:
            self.multihost.run_command(['pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                                        '-h', self.multihost.hostname, '-p', self.sys_http_port,
                                        '-n', user_nick, self.subsystem, 'group-member-add', groupid, userid])
        except CalledProcessError as E:
            raise PkiLibException('Unable to add %s to role %s' % (userid, groupid), E.returncode)
        else:
            self.multihost.log.info("Successfully added user %s to role %s" % (userid, groupid))

    def create_user_cert(self, cert_subject, profile=None):
        ''' Add certificate to the subsystem user and add certificate to certdb
        :param str cert_subject: Subject to be used to create certificate reqeust
        :returns None
        :raises PkiLibException if create of certificate request or approving fails
        '''
        if profile is None:
            profile = 'caUserCert'
        try:
            output = self.multihost.run_command([
                'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                '-h', self.multihost.hostname, '-p', self.sys_http_port,
                '-n', self.sys_admin_nick, 'client-cert-request', cert_subject,
                '--profile', profile])
        except CalledProcessError as E:
            raise PkiLibException('Unable to create cert with subject %s' %
                                  (cert_subject), E.returncode)
        else:
            request_id = re.search('Request ID: [\w]*', output.stdout_text)
            r_id = request_id.group().split(':')[1].strip()
            try:
                output = self.multihost.run_command([
                    'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd, '-h',
                    self.multihost.hostname, '-p', self.sys_http_port, '-n',
                    self.sys_admin_nick, 'cert-request-review', r_id, '--action', 'approve'])
            except CalledProcessError as E:
                raise PkiLibException(
                    'Unable to approve certificate request %s' % (r_id), E.returncode)
            else:
                cert_id = re.search('Certificate ID: [\w]*', output.stdout_text)
                c_id = cert_id.group().split(':')[1].strip()
                return c_id

    def import_cert_to_certdb(self, cert_serial_number, nickname):
        ''' Import certificate to certdb
        :param str cert_serial_number: serial Number of the cert
        :param str nickname: nickname to be used to import the cert to certdb
        :Returns None
        :Raises PkiLibException if importing the cert fails
        '''
        try:
            self.multihost.run_command([
                'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                '-h', self.multihost.hostname, '-p', self.sys_http_port,
                '-n', self.sys_admin_nick, 'client-cert-import',
                nickname, '--serial', cert_serial_number])
        except CalledProcessError as E:
            raise PkiLibException('Unable to import cert %s to certdb %s' % (
                cert_serial_number, self.nssdb_dir), E.returncode)
        else:
            self.multihost.log.info("Successfully added cert %s to certdb %s with nick %s" % (
                cert_serial_number, self.nssdb_dir, nickname))

    def submit_xml_request(self, profile_id, csr=None, user_nick=None, subject_input=None):
        ''' Submit xml request to CA subsystem
        :param str profile_id: Profile Name to which the certificate request should be submitted
        :param str csr: Certificat request in pem format with headers
        :param str user_nick: Certificate Nick to be used to submit the request, if none, CA Admin
            cert will be used to submit the request
        :param dict subject_input: if no csr is provided, the a dictionary containing details of
            CN, E, Country, OU etc, should be provided to generate certificate request, [Not yet implemented]
        :Returns str list: Certificateserial Number and Request ID
        :Raises PkiLibException if unable to submit request
        '''
        if user_nick is None:
            user_nick = self.sys_admin_nick
        profile_xml_path = '%s/%s.xml' % (self.nssdb_dir, profile_id)
        profile_xml_update_path = '%s/%s-update.xml' % (self.nssdb_dir, profile_id)
        try:
            output = self.multihost.run_command([
                'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                '-h', self.multihost.hostname, '-p', self.sys_http_port,
                '-n', user_nick, 'cert-request-profile-show',
                profile_id, '--output', profile_xml_path])
        except CalledProcessError as E:
            raise PkiLibException(
                'Unable to get the profile xml of profile id:%s' % (profile_id), E.returncode)
        else:
            pki_obj = PkiTools()
            if csr is None:
                print("yet to be done")
            else:
                output = self.multihost.transport.get_file(
                    profile_xml_path, '%s-update.xml' % (profile_id))
                pki_obj.update_profile_xml(csr, '%s-update.xml' % (profile_id))
                output = self.multihost.transport.put_file(
                    '%s-update.xml' % (profile_id), profile_xml_update_path)
            try:
                output = self.multihost.run_command([
                    'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                    '-h', self.multihost.hostname, '-p', self.sys_http_port,
                    '-n', user_nick, 'cert-request-submit', profile_xml_update_path])
            except CalledProcessError as E:
                raise PkiLibException('Unable to submit xml request :%s' %
                                      (profile_xml_update_path), E.returncode)
            else:
                request_id = re.search('Request ID: [\w]*', output.stdout_text)
                r_id = request_id.group().split(':')[1].strip()
                try:
                    output = self.multihost.run_command([
                        'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                        '-h', self.multihost.hostname, '-p', self.sys_http_port,
                        '-n', user_nick, 'cert-request-review', r_id, '--action', 'approve'])
                except CalledProcessError as E:
                    raise PkiLibException(
                        'Unable to approve request %s as %s' % (r_id, user_nick), E.returncode)
                else:
                    cert_id = re.search('Certificate ID: [\w]*', output.stdout_text)
                    c_id = cert_id.group().split(':')[1].strip()
                    return [c_id, r_id]

    def add_new_profile(self, profile_id, profile_xml, user_nick=None):
        ''' Add a new profile xml as user_nick
        :param str profile_id: Profile Name
        :param str profile_xml: Path of the profile xml to be added
        :param str user_nick: Certificate Nick to be used to submit the request, if none, CA Admin
            cert will be used to submit the request
        :Returns None
        :Raises PkiLibException if profile could not be added
        '''
        if user_nick is None:
            user_nick = self.sys_admin_nick
        destination_profile_path = "%s/new-%s.xml" % (self.multihost.config.test_dir, profile_id)
        try:
            self.multihost.transport.put_file(profile_xml, destination_profile_path)
        except IOError as E:
            raise PkiLibException("Unable to copy file")
        try:
            self.multihost.run_command([
                'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                '-h', self.multihost.hostname, '-p', self.sys_http_port,
                '-n', user_nick, 'ca-profile-add', destination_profile_path])
        except CalledProcessError as E:
            raise PkiLibException('Unable to add profile :%s' % (profile_xml), E.returncode)
        else:
            self.multihost.log.info("Successfully added profile %s" % (profile_xml))

    def enable_profile(self, profile_id, user_nick=None):
        ''' Enable a profile as user_nick
        :param str profile_id: Profile Name
        :param str user_nick: Certificate Nick to be used to submit the request, if none, CA Admin
            cert will be used to submit the request
        :Returns None
        :Raises PkiLibException if profile could not be enabled
        '''
        if user_nick is None:
            user_nick = self.sys_admin_nick
        try:
            self.multihost.run_command([
                'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                '-h', self.multihost.hostname, '-p', self.sys_http_port,
                '-n', user_nick, 'ca-profile-enable', profile_id])
        except CalledProcessError as E:
            raise PkiLibException('Unable to enable profile :%s' % (profile_id), E.returncode)
        else:
            self.multihost.log.info("Successfully enabled profile %s " % (profile_id))

    def disable_profile(self, profile_id, user_nick=None):
        ''' Disable a profile as user_nick
        :param str profile_id: Profile Name
        :param str user_nick: Certificate Nick to be used to submit the request, if none, CA Admin
            cert will be used to submit the request
        :Returns None
        :Raises PkiLibException if profile could not be enabled
        '''
        if user_nick is None:
            user_nick = self.sys_admin_nick
        try:
            self.multihost.run_command([
                'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                '-h', self.multihost.hostname, '-p', self.sys_http_port,
                '-n', user_nick, 'ca-profile-disable', profile_id])
        except CalledProcessError as E:
            raise PkiLibException('Unable to enable profile :%s' % (profile_id), E.returncode)
        else:
            self.multihost.log.info("Successfully disabled profile %s " % (profile_id))

    def cert_show(self, cert_serial_no):
        ''' Run cert show on cert serial number
        :param str cert_serial_no: Certficiate Serial Number
        :Returns None
        :Raises PkiLibException if profile could not be enabled
        '''
        output_file = "%s/%s.pem" % (self.multihost.config.test_dir, cert_serial_no)
        try:
            output = self.multihost.run_command([
                'pki', '-d', self.nssdb_dir, '-c', self.nssdb_pwd,
                '-h', self.multihost.hostname, '-p', self.sys_http_port,
                '-n', self.sys_admin_nick, 'cert-show', cert_serial_no,
                '--pretty', '--output', output_file])
        except CalledProcessError as E:
            raise PkiLibException(
                'Unable run cert-show on serial number :%s' % (cert_serial_no), E.returncode)
        else:
            return [output.stdout_text, output_file]
