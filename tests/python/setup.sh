#!/bin/sh
set -e

if [ -d /etc/pki/pki-tomcat-tests/kra ]; then
    pkidestroy -i pki-tomcat-tests -s KRA
fi

if [ -d /etc/pki/pki-tomcat-tests/ca ]; then
    pkidestroy -i pki-tomcat-tests -s CA
fi

if [ -d /etc/dirsrv/slapd-pki-tomcat-tests ]; then
    remove-ds.pl -f -i slapd-pki-tomcat-tests
fi

setup-ds.pl --silent \
    General.FullMachineName=`hostname` \
    General.SuiteSpotUserID=nobody \
    General.SuiteSpotGroup=nobody \
    slapd.ServerPort=20389 \
    slapd.ServerIdentifier=pki-tomcat-tests \
    slapd.Suffix=dc=example,dc=com \
    slapd.RootDN="cn=Directory Manager" \
    slapd.RootDNPwd=Secret123

pkispawn -v -f pki.cfg -s CA
pkispawn -v -f pki.cfg -s KRA

echo 'Exporting CA admin cert to /tmp/auth.pem'
openssl pkcs12 \
    -in /root/.dogtag/pki-tomcat-tests/ca_admin_cert.p12 \
    -out /tmp/auth.pem \
    -nodes \
    -passin pass:Secret123
