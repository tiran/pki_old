from pytest_multihost import make_multihost_fixture
from .exceptions import RPMException
import pytest_multihost.config
import pytest_multihost.host
import logging
import pytest

"""
qe_class provides the expansion to the py.test multihost plugin for CS Testing

#Initialize pytest_multihost.config with default variables
#:param kwargs:
"""


class QeConfig(pytest_multihost.config.Config):
    """
    QeConfig subclass of multihost plugin to extend functionality
    """
    extra_init_args = {}

    def __init__(self, **kwargs):
        self.log = self.get_logger('%s.%s' % (__name__, type(self).__name__))
        pytest_multihost.config.Config.__init__(self, **kwargs)

    def get_domain_class(self):
        """
        return custom domain class.  This is needed to fully extend the config for
        custom multihost plugin extensions.

            :param None:

            :return None:
        """
        return QeDomain

    def get_logger(self, name):
        """
        Override get_logger to set logging level

            :param str name:
            :return obj log:
        """
        log = logging.getLogger(name)
        log.propagate = False
        if not log.handlers:
            # set log Level
            log.setLevel(logging.DEBUG)
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            # set formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            log.addHandler(handler)
        return log


class QeDomain(pytest_multihost.config.Domain):
    """
    QeDomain subclass of multihost plugin domain class.
    """

    def __init__(self, config, name, domain_type):
        """
        Subclass of pytest_multihost.config.Domain

        :param obj config: config config
        :param str name: Name
        :param str domain_type:

        :return None:
        """

        self.type = str(domain_type)
        self.config = config
        self.name = str(name)
        self.hosts = []

    def get_host_class(self, host_dict):
        """
        return custom host class
        """
        return QeHost


class QeHost(pytest_multihost.host.Host):
    """
    QeHost subclass of multihost plugin host class.  This extends functionality
    of the host class for IPA QE purposes.  Here we add support functions that
    will be very widely used across tests and must be run on any or all hosts
    in the environment.
    """

    def __init__(self, domain, hostname, role, ip=None, external_hostname=None):
        pytest_multihost.host.Host.__init__(
            self, domain, hostname, role, ip=None, external_hostname=None)
        self.redhatrelease = self.GetDistro()
        self.hostname = self.gethostname()
        self.rhel_pki_pkg_list = [
            'redhat-pki', 'pki-console', 'redhat-pki-theme', 'idm-console-framework', '389-ds-base']
        self.fedora_pki_pkg_list = ['dogtag-pki', 'pki-console', 'dogtag-pki-theme', '389-ds']

    def qerun(self, command, stdin_text=None, exp_returncode=0, exp_output=None):
        """
        qerun :: <command> [stdin_text=<string to pass as stdin>]
            [exp_returncode=<retcode>]
            [<exp_output=<string to check from output>]
        - function to run a command and check return code and output

            :param str command: Command
            :param str stdin_text: Stdin
            :param int exp_returncode: Return code (default 0)
            :param str exp_output: Check the expected output
        """
        cmd = self.run_command(command, stdin_text, raiseonerr=False)
        if cmd.returncode != exp_returncode:
            pytest.xfail("returncode mismatch.")
            print("GOT: ", cmd.returncode)
            print("EXPECTED: ", exp_returncode)

        if exp_output is None:
            print("Not checking expected output")

        elif cmd.stdout_text.find(exp_output) == 0:
            pytest.xfail("expected output not found")
            print("GOT: ", cmd.stdout_text)
            print("EXPECTED: ", exp_output)

        print("COMMAND SUCCEEDED!")

    def GetDistro(self):
        """ Return contents of /etc/redhatrelease """

        cmd = self.run_command(
            ['cat', '/etc/redhat-release'], raiseonerr=False)
        if cmd.returncode != 0:
            distro = 'unknown Distro'
        else:
            distro = cmd.stdout_text.strip()
        return distro

    def gethostname(self):
        """ Return system hostname """
        cmd = self.run_command(['hostname'], raiseonerr=False)
        return cmd.stdout_text.strip()

    def yum_install(self, package):
        """ Install packages through yum """
        cmd = self.run_command(['yum', '-y', 'install', package], raiseonerr=False)
        return cmd

    def dnf_install(self, package):
        """ Install packges through dnf """
        cmd = self.run_command(['dnf', '-y', 'install', package], raiseonerr=False)
        return cmd

    def yum_uninstall(self, package):
        """ Uninstall packages through yum """
        cmd = self.run_command(['yum', '-y', 'remove', package], raiseonerr=False)
        return cmd

    def dnf_uninstall(self, package):
        """ Uninstall packages through dnf """
        cmd = self.run_command(['dnf', '-y', 'remove', package], raiseonerr=False)
        return cmd

    def install_basic_packages(self):
        if 'Red Hat' in self.redhatrelease:
            for rpm in self.rhel_pki_pkg_list:
                output = self.yum_install(rpm)
                if output.returncode != 0:
                    raise RPMException('Unable to install %s package' % rpm, output.returncode)
                else:
                    return output.stdout_text
        if 'Fedora' in self.redhatrelease:
            for rpm in self.fedora_pki_pkg_list:
                output = self.dnf_install(rpm)
                if output.returncode != 0:
                    raise RPMException('Unable to install %s package' % rpm, output.returncode)
                else:
                    return output.stdout_text


@pytest.yield_fixture(scope="session", autouse=True)
def session_multihost(request):
    mh = make_multihost_fixture(request,
                                descriptions=[
                                    {
                                        'type': 'pki',
                                        'hosts':
                                        {
                                            'master': pytest.num_masters,
                                            'clone': pytest.num_clones

                                        }
                                    },
                                ],
                                config_class=QeConfig)
    mh.domain = mh.config.domains[0]
    mh.master = mh.domain.hosts_by_role('master')
    mh.clone = mh.domain.hosts_by_role('clone')
    yield mh
