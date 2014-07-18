#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-show   Show users 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Asha Akkiangady <aakkiang@redhat.com>
#            Laxmi Sunkara <lsunkara@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

######################################################################################
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
#pki-user-cli-user-add-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
run_pki-user-cli-user-show-ca_tests(){
    #local variables
    user1=ca_agent2
    user1fullname="Test ca_agent"
    user2=abcdefghijklmnopqrstuvwxyx12345678
    user3=abc#
    user4=abc$
    user5=abc@
    user6=abc?
    user7=0

    rlPhaseStartSetup "pki_user_cli_user_show-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_show-configtest: pki user-show configuration test"
        rlRun "pki user-show --help > $TmpDir/pki_user_show_cfg.out 2>&1" \
               0 \
               "pki user-show"
        rlAssertGrep "usage: user-show <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_show_cfg.out"
        rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_show_cfg.out"
        rlAssertNotGrep "Error: Certificate database not initialized." "$TmpDir/pki_user_show_cfg.out"
    rlPhaseEnd

     ##### Tests to show CA users ####
    rlPhaseStartTest "pki_user_cli_user_show-CA-001: Add user to CA using CA_adminV and show user"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=\"$user1fullname\" $user1" \
		    0 \
                    "Add user $user1 using CA_adminV"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user1 > $TmpDir/pki-user-show-ca-001.out" \
		    0 \
		    "Show user $user1"
        rlAssertGrep "User \"$user1\"" "$TmpDir/pki-user-show-ca-001.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-show-ca-001.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-show-ca-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-002: maximum length of user id"
	user2=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user2" \
		    0 \
                    "Add user $user2 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user2 > $TmpDir/pki-user-show-ca-001_1.out" \
                    0 \
                    "Show $user2 user"
        rlAssertGrep "User \"$user2\"" "$TmpDir/pki-user-show-ca-001_1.out"
	actual_userid_string=`cat $TmpDir/pki-user-show-ca-001_1.out | grep 'User ID:' | xargs echo`
        expected_userid_string="User ID: $user2"
        if [[ $actual_userid_string = $expected_userid_string ]] ; then
                rlPass "User ID: $user2 found"
        else
                rlFail "User ID: $user2 not found"
        fi
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_1.out"
	
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-003: User id with # character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user3" \
		    0 \
                    "Add user $user3 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user3 > $TmpDir/pki-user-show-ca-001_2.out" \
                    0 \
                    "Show $user3 user"
        rlAssertGrep "User \"$user3\"" "$TmpDir/pki-user-show-ca-001_2.out"
        rlAssertGrep "User ID: $user3" "$TmpDir/pki-user-show-ca-001_2.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-004: User id with $ character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user4" \
		    0 \
                    "Add user $user4 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user4 > $TmpDir/pki-user-show-ca-001_3.out" \
                    0 \
                    "Show $user4 user"
        rlAssertGrep "User \"$user4\"" "$TmpDir/pki-user-show-ca-001_3.out"
        rlAssertGrep "User ID: abc\\$" "$TmpDir/pki-user-show-ca-001_3.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_3.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-005: User id with @ character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user5" \
                    0 \
                    "Add $user5 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user5 > $TmpDir/pki-user-show-ca-001_4.out" \
                    0 \
                    "Show $user5 user"
        rlAssertGrep "User \"$user5\"" "$TmpDir/pki-user-show-ca-001_4.out"
        rlAssertGrep "User ID: $user5" "$TmpDir/pki-user-show-ca-001_4.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_4.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-006: User id with ? character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user6" \
                    0 \
                    "Add $user6 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user6 > $TmpDir/pki-user-show-ca-001_5.out" \
                    0 \
                    "Show $user6 user"
        rlAssertGrep "User \"$user6\"" "$TmpDir/pki-user-show-ca-001_5.out"
        rlAssertGrep "User ID: $user6" "$TmpDir/pki-user-show-ca-001_5.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_5.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-007: User id as 0"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test $user7" \
                    0 \
                    "Add user $user7 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show $user7 > $TmpDir/pki-user-show-ca-001_6.out" \
                    0 \
                    "Show user $user7"
        rlAssertGrep "User \"$user7\"" "$TmpDir/pki-user-show-ca-001_6.out"
        rlAssertGrep "User ID: $user7" "$TmpDir/pki-user-show-ca-001_6.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_6.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-008: --email with maximum length"
	email=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=\"$email\" u1" \
		    0 \
		    "Added user using CA_adminV with maximum --email length"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u1 > $TmpDir/pki-user-show-ca-001_7.out" \
                    0 \
                    "Show user u1"
        rlAssertGrep "User \"u1\"" "$TmpDir/pki-user-show-ca-001_7.out"
        rlAssertGrep "User ID: u1" "$TmpDir/pki-user-show-ca-001_7.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_7.out"
	actual_email_string=`cat $TmpDir/pki-user-show-ca-001_7.out | grep Email: | xargs echo`
        expected_email_string="Email: $email"
        if [[ $actual_email_string = $expected_email_string ]] ; then
                rlPass "Email: $email found"
        else
                rlFail "Email: $email not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-009: --email with maximum length and symbols"
	email=`cat /dev/urandom | tr -dc 'a-zA-Z0-9!?@~#*^_+$' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email='$email'  u2" \
		    0 \
		    "Added user using CA_adminV with maximum --email length and character symbols in it"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u2 > $TmpDir/pki-user-show-ca-001_8.out" \
                    0 \
                    "Show user u2"
        rlAssertGrep "User \"u2\"" "$TmpDir/pki-user-show-ca-001_8.out"
        rlAssertGrep "User ID: u2" "$TmpDir/pki-user-show-ca-001_8.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_8.out"
	actual_email_string=`cat $TmpDir/pki-user-show-ca-001_8.out | grep Email: | xargs echo`
        expected_email_string="Email: $email"
        if [[ $actual_email_string = $expected_email_string ]] ; then
                rlPass "Email: $email found"
        else
                rlFail "Email: $email not found"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-010: --email with # character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=#  u3" \
                    0 \
                    "Add user u3 using pki CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u3 > $TmpDir/pki-user-show-ca-001_9.out" \
		     0 \
                    "Add user u3"
        rlAssertGrep "User \"u3\"" "$TmpDir/pki-user-show-ca-001_9.out"
        rlAssertGrep "User ID: u3" "$TmpDir/pki-user-show-ca-001_9.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_9.out"
        rlAssertGrep "Email: #" "$TmpDir/pki-user-show-ca-001_9.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-011: --email with * character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=*  u4" \
		    0 \
                    "Add user u4 using pki CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u4 > $TmpDir/pki-user-show-ca-001_10.out" \
                    0 \
                    "Show user u4 using CA_adminV"
        rlAssertGrep "User \"u4\"" "$TmpDir/pki-user-show-ca-001_10.out"
        rlAssertGrep "User ID: u4" "$TmpDir/pki-user-show-ca-001_10.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_10.out"
        rlAssertGrep "Email: *" "$TmpDir/pki-user-show-ca-001_10.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-012: --email with $ character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=$  u5" \
		    0 \
                    "Add user u5 using pki CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u5 > $TmpDir/pki-user-show-ca-001_11.out" \
                    0 \
                    "Show user u5 using CA_adminV"
        rlAssertGrep "User \"u5\"" "$TmpDir/pki-user-show-ca-001_11.out"
        rlAssertGrep "User ID: u5" "$TmpDir/pki-user-show-ca-001_11.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_11.out"
        rlAssertGrep "Email: \\$" "$TmpDir/pki-user-show-ca-001_11.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-013: --email as number 0"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --email=0  u6" \
		    0 \
                    "Add user u6 using pki CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u6 > $TmpDir/pki-user-show-ca-001_12.out" \
                    0 \
                    "Show user u6 using CA_adminV"
        rlAssertGrep "User \"u6\"" "$TmpDir/pki-user-show-ca-001_12.out"
        rlAssertGrep "User ID: u6" "$TmpDir/pki-user-show-ca-001_12.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_12.out"
        rlAssertGrep "Email: 0" "$TmpDir/pki-user-show-ca-001_12.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-014: --state with maximum length"
	state=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=\"$state\" u7 " \
		    0 \
                    "Add user u7 using pki CA_adminV with maximum --state length"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u7 > $TmpDir/pki-user-show-ca-001_13.out" \
                    0 \
                    "Show user u7 using CA_adminV"
        rlAssertGrep "User \"u7\"" "$TmpDir/pki-user-show-ca-001_13.out"
        rlAssertGrep "User ID: u7" "$TmpDir/pki-user-show-ca-001_13.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_13.out"
	actual_state_string=`cat $TmpDir/pki-user-show-ca-001_13.out | grep State: | xargs echo`
        expected_state_string="State: $state"
        if [[ $actual_state_string = $expected_state_string ]] ; then
                rlPass "State: $state found in $TmpDir/pki-user-show-ca-001_13.out"
        else
                rlFail "State: $state not found in $TmpDir/pki-user-show-ca-001_13.out"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-015: --state with maximum length and symbols"
	state=`cat /dev/urandom | tr -dc 'a-zA-Z0-9!?@~#*^_+$' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state='$state' u8" \
		    0 \
                    "Add user u8 using pki CA_adminV with maximum --state length and symbols"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u8 > $TmpDir/pki-user-show-ca-001_14.out" \
                    0 \
                    "Show user u8 using CA_adminV"
        rlAssertGrep "User \"u8\"" "$TmpDir/pki-user-show-ca-001_14.out"
        rlAssertGrep "User ID: u8" "$TmpDir/pki-user-show-ca-001_14.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_14.out"
	actual_state_string=`cat $TmpDir/pki-user-show-ca-001_14.out | grep State: | xargs echo`
        expected_state_string="State: $state"
        if [[ $actual_state_string = $expected_state_string ]] ; then
                rlPass "State: $state found in $TmpDir/pki-user-show-ca-001_14.out"
        else
                rlFail "State: $state not found in $TmpDir/pki-user-show-ca-001_14.out"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-016: --state with # character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=#  u9" \
		    0 \
                    "Added user using CA_adminV with --state # character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u9 > $TmpDir/pki-user-show-ca-001_15.out" \
                    0 \
                    "Show user u9 using CA_adminV"
        rlAssertGrep "User \"u9\"" "$TmpDir/pki-user-show-ca-001_15.out"
        rlAssertGrep "User ID: u9" "$TmpDir/pki-user-show-ca-001_15.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_15.out"
        rlAssertGrep "State: #" "$TmpDir/pki-user-show-ca-001_15.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-017: --state with * character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=*  u10" \
		    0 \
                    "Adding user using CA_adminV with --state * character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u10 > $TmpDir/pki-user-show-ca-001_16.out" \
                    0 \
                    "Show user u10 using CA_adminV"
        rlAssertGrep "User \"u10\"" "$TmpDir/pki-user-show-ca-001_16.out"
        rlAssertGrep "User ID: u10" "$TmpDir/pki-user-show-ca-001_16.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_16.out"
        rlAssertGrep "State: *" "$TmpDir/pki-user-show-ca-001_16.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-018: --state with $ character"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=$  u11" \
		    0 \
                    "Adding user using CA_adminV with --state $ character"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u11 > $TmpDir/pki-user-show-ca-001_17.out" \
                    0 \
                    "Show user u11 using CA_adminV"
        rlAssertGrep "User \"u11\"" "$TmpDir/pki-user-show-ca-001_17.out"
        rlAssertGrep "User ID: u11" "$TmpDir/pki-user-show-ca-001_17.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_17.out"
        rlAssertGrep "State: \\$" "$TmpDir/pki-user-show-ca-001_17.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-019: --state as number 0"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --state=0  u12" \
		    0 \
                    "Adding user using CA_adminV with --state 0"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u12 > $TmpDir/pki-user-show-ca-001_18.out" \
                    0 \
                    "Show pki CA_adminV user"
        rlAssertGrep "User \"u12\"" "$TmpDir/pki-user-show-ca-001_18.out"
        rlAssertGrep "User ID: u12" "$TmpDir/pki-user-show-ca-001_18.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_18.out"
        rlAssertGrep "State: 0" "$TmpDir/pki-user-show-ca-001_18.out"
    rlPhaseEnd

	#https://www.redhat.com/archives/pki-users/2010-February/msg00015.html
    rlPhaseStartTest "pki_user_cli_user_show-CA-020: --phone with maximum length"
	phone=`cat /dev/urandom | tr -dc '0-9' | fold -w 2048 | head -n 1`
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --phone=\"$phone\" u13" \
		    0 \
                    "Adding user using CA_adminV with maximum --phone length"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u13 > $TmpDir/pki-user-show-ca-001_19.out" \
                    0 \
                    "Show user u13 using CA_adminV"
        rlAssertGrep "User \"u13\"" "$TmpDir/pki-user-show-ca-001_19.out"
        rlAssertGrep "User ID: u13" "$TmpDir/pki-user-show-ca-001_19.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_19.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-show-ca-001_19.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-021: --phone as negative number -1230"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --phone=-1230  u14" \
		    0 \
                    "Adding user using CA_adminV with --phone as negative number -1230"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u14 > $TmpDir/pki-user-show-ca-001_24.out" \
                    0 \
                    "Show user u14 using CA_adminV"
        rlAssertGrep "User \"u14\"" "$TmpDir/pki-user-show-ca-001_24.out"
        rlAssertGrep "User ID: u14" "$TmpDir/pki-user-show-ca-001_24.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_24.out"
        rlAssertGrep "Phone: -1230" "$TmpDir/pki-user-show-ca-001_24.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-022: --type as Auditors"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=Auditors u15" \
		    0 \
                    "Adding user using CA_adminV with --type as Auditors"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u15 > $TmpDir/pki-user-show-ca-001_25.out" \
                    0 \
                    "Show user u15 using CA_adminV"
        rlAssertGrep "User \"u15\"" "$TmpDir/pki-user-show-ca-001_25.out"
        rlAssertGrep "User ID: u15" "$TmpDir/pki-user-show-ca-001_25.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_25.out"
        rlAssertGrep "Type: Auditors" "$TmpDir/pki-user-show-ca-001_25.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-023: --type Certificate Manager Agents"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Certificate Manager Agents\" u16" \
		    0 \
                    "Adding user using CA_adminV with --type Certificate Manager Agents"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u16 > $TmpDir/pki-user-show-ca-001_26.out" \
                    0 \
                    "Show user u16 using CA_adminV"
        rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-show-ca-001_26.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-show-ca-001_26.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_26.out"
        rlAssertGrep "Type: Certificate Manager Agents" "$TmpDir/pki-user-show-ca-001_26.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-024: --type Registration Manager Agents"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Registration Manager Agents\"  u17" \
		    0 \
                    "Adding user using CA_adminV with --type Registration Manager Agents"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u17 > $TmpDir/pki-user-show-ca-001_27.out" \
                    0 \
                    "Show user u17 using CA_adminV"
        rlAssertGrep "User \"u17\"" "$TmpDir/pki-user-show-ca-001_27.out"
        rlAssertGrep "User ID: u17" "$TmpDir/pki-user-show-ca-001_27.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_27.out"
        rlAssertGrep "Type: Registration Manager Agents" "$TmpDir/pki-user-show-ca-001_27.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-025: --type Subsytem Group"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Subsytem Group\"  u18" \
		     0 \
                    "Adding user using CA_adminV with --type Subsytem Group"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u18 > $TmpDir/pki-user-show-ca-001_28.out" \
                    0 \
                    "Show user u18 using CA_adminV"
        rlAssertGrep "User \"u18\"" "$TmpDir/pki-user-show-ca-001_28.out"
        rlAssertGrep "User ID: u18" "$TmpDir/pki-user-show-ca-001_28.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_28.out"
        rlAssertGrep "Type: Subsytem Group" "$TmpDir/pki-user-show-ca-001_28.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-026: --type Security Domain Administrators"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Security Domain Administrators\" u19" \
		    0 \
                    "Adding user using CA_adminV with --type Security Domain Administrators"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u19 > $TmpDir/pki-user-show-ca-001_29.out" \
                    0 \
                    "Show user u19 using CA_adminV"
        rlAssertGrep "User \"u19\"" "$TmpDir/pki-user-show-ca-001_29.out"
        rlAssertGrep "User ID: u19" "$TmpDir/pki-user-show-ca-001_29.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_29.out"
        rlAssertGrep "Type: Security Domain Administrators" "$TmpDir/pki-user-show-ca-001_29.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-027: --type ClonedSubsystems"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=ClonedSubsystems u20" \
		    0 \
		    "Adding user using CA_adminV with --type ClonedSubsystems"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u20 > $TmpDir/pki-user-show-ca-001_30.out" \
                    0 \
                    "Show user u20 using CA_adminV"
        rlAssertGrep "User \"u20\"" "$TmpDir/pki-user-show-ca-001_30.out"
        rlAssertGrep "User ID: u20" "$TmpDir/pki-user-show-ca-001_30.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_30.out"
        rlAssertGrep "Type: ClonedSubsystems" "$TmpDir/pki-user-show-ca-001_30.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-028: --type Trusted Managers"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test --type=\"Trusted Managers\" u21" \
		    0 \
                    "Adding user using CA_adminV with --type Trusted Managers"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show u21 > $TmpDir/pki-user-show-ca-001_31.out" \
                    0 \
                    "Show user u21 using CA_adminV"
        rlAssertGrep "User \"u21\"" "$TmpDir/pki-user-show-ca-001_31.out"
        rlAssertGrep "User ID: u21" "$TmpDir/pki-user-show-ca-001_31.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-show-ca-001_31.out"
        rlAssertGrep "Type: Trusted Managers" "$TmpDir/pki-user-show-ca-001_31.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-029: Show user with -t ca option"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  u22" \
		    0 \
                    "Adding user u22 using CA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-show u22 > $TmpDir/pki-user-show-ca-001_32.out" \
                    0 \
                    "Show user u22 using CA_adminV"
        rlAssertGrep "User \"u22\"" "$TmpDir/pki-user-show-ca-001_32.out"
        rlAssertGrep "User ID: u22" "$TmpDir/pki-user-show-ca-001_32.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-show-ca-001_32.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-030: Add a user -- all options provided"
	email="ca_agent2@myemail.com"
	user_password="agent2Password"
        phone="1234567890"
        state="NC"
        type="Administrators"
	rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                    --type $type \
                     u23" \
		    0 \
                    "Adding user u23 using CA_adminV" 
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-show u23 > $TmpDir/pki-user-show-ca-001_33.out" \
                    0 \
                    "Show user u23 using CA_adminV"
        rlAssertGrep "User \"u23\"" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "Type: $type" "$TmpDir/pki-user-show-ca-001_33.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-show-ca-001_33.out"
    rlPhaseEnd

    #Negative Cases
    rlPhaseStartTest "pki_user_cli_user_show-CA-031: Missing required option user id"
	command="pki -d $CERTDB_DIR  -n CA_adminV  -c $CERTDB_DIR_PASSWORD -t ca user-show" 
        rlLog "Executing $command"
        errmsg="Error: No User ID specified."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot show user without user id"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-032: Checking if user id case sensitive "
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                    user-show U23 > $TmpDir/pki-user-show-ca-001_35.out 2>&1" \
                    0 \
                    "User ID is not case sensitive"
	rlAssertGrep "User \"U23\"" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "User ID: u23" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "Type: $type" "$TmpDir/pki-user-show-ca-001_35.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-show-ca-001_35.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-033: Should not be able to show user using a revoked cert CA_adminR"
        command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD user-show u23"
        rlLog "Executing $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show user u23 using a admin having revoked cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-034: Should not be able to show user using a agent with revoked cert CA_agentR"
        command="pki -d $CERTDB_DIR  -n CA_agentR -c $CERTDB_DIR_PASSWORD user-show u23"
        rlLog "Executing $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show user u23 using a agent having revoked cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-035: Should not be able to show user using a valid agent CA_agentV user"
        command="pki -d $CERTDB_DIR -n CA_agentV -c $CERTDB_DIR_PASSWORD user-show u23"
        rlLog "Executing $command"
        errmsg="ForbiddenException: Authorization failed"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show user u23 using a agent cert"
	rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/965"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-036: Should not be able to show user using a CA_agentR user"
        command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD user-show u23"
        rlLog "Executing $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show user u23 using a revoked agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-037: Should not be able to show user using admin user with expired cert CA_adminE"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD user-show u23"
        rlLog "Executing $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show user u23 using an expired admin cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-038: Should not be able to show user using CA_agentE cert"
	#Set datetime 2 days ahead
        rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
	rlRun "date"
        command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD user-show u23"
        rlLog "Executing $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show user u23 using a agent cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-039: Should not be able to show user using a CA_auditV"
        command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD user-show u23"
        rlLog "Executing $command"
        errmsg="ForbiddenException: Authorization failed"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show user u23 using a audit cert"
	rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/965"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-040: Should not be able to show user using a CA_operatorV"
        command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD user-show u23"
        rlLog "Executing $command"
        errmsg="ForbiddenException: Authorization failed"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to show user u23 using a operator cert"
	rlLog "PKI TICKET :: https://fedorahosted.org/pki/ticket/965"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-041: Should not be able to show user using a cert created from a untrusted CA CA_adminUTCA"
        rlLog "Executing: pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    user-show u23"
        rlRun "pki -d /tmp/untrusted_cert_db \
                   -n CA_adminUTCA \
                   -c Password \
                    user-show u23 > $TmpDir/pki-user-show-ca-adminUTCA-002.out 2>&1" \
                    255 \
                    "Should not be able to show user u23 using a untrusted cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-user-show-ca-adminUTCA-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-ca-042: Should not be able to show user using a user cert"
        #Create a user cert
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
        local valid_serialNumber
        local temp_out="$TmpDir/usercert-show.out"
        rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"pki User1\" \"pkiUser1\" \
                \"pkiuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 "Generating  pkcs10 Certificate Request"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"CA_agentV\" ca-cert-request-review $ret_requestid \
                --action approve 1"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"CA_agentV\" ca-cert-request-review $ret_requestid \
                --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
        rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
        rlLog "pki cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
        rlRun "pki cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
        valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
        rlLog "valid_serialNumber=$valid_serialNumber"
        #Import user certs to $TEMP_NSS_DB
        rlRun "pki cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
        rlRun "certutil -d $TEMP_NSS_DB -A -n pkiUser1 -i $temp_out  -t "u,u,u""
        local expfile="$TmpDir/expfile_pkiuser1.out"
        rlLog "Executing: pki -d $TEMP_NSS_DB \
                   -n pkiUser1 \
                   -c Password \
                    user-find --start=1 --size=5"
        echo "spawn -noecho pki -d $TEMP_NSS_DB -n pkiUser1 -c Password user-show u13" > $expfile
        echo "expect \"WARNING: UNTRUSTED ISSUER encountered on 'CN=$HOSTNAME,O=$CA_DOMAIN Security Domain' indicates a non-trusted CA cert 'CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain'
Import CA certificate (Y/n)? \"" >> $expfile
        echo "send -- \"Y\r\"" >> $expfile
        echo "expect \"CA server URI \[http://$HOSTNAME:$CA_UNSECURE_PORT/ca\]: \"" >> $expfile
        echo "send -- \"\r\"" >> $expfile
        echo "expect eof" >> $expfile
	echo "catch wait result" >> $expfile
        echo "exit [lindex \$result 3]" >> $expfile
        rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pki-user-show-ca-pkiUser1-002.out 2>&1" 255 "Should not be able to find users using a user cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-user-show-ca-pkiUser1-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-043: user id length exceeds maximum limit defined in the schema"
        user_length_exceed_max=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10000 | head -n 1`
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show  \"$user_length_exceed_max\""
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show \"$user_length_exceed_max\" > $TmpDir/pki-user-show-ca-001_50.out 2>&1" \
                    255 \
                    "Show user using CA_adminV with user id length exceed maximum defined in ldap schema"
        rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki-user-show-ca-001_50.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-044: user id with i18n characters"
        rlLog "user-add userid ÖrjanÄke with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÖrjanÄke' > $TmpDir/pki-user-show-ca-001_56.out 2>&1" \
                    0 \
                    "Adding uid ÖrjanÄke with i18n characters"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show 'ÖrjanÄke'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show 'ÖrjanÄke' > $TmpDir/pki-user-show-ca-001_56_2.out" \
                    0 \
                    "Show user 'ÖrjanÄke'"
        rlAssertGrep "User \"ÖrjanÄke\"" "$TmpDir/pki-user-show-ca-001_56_2.out"
        rlAssertGrep "User ID: ÖrjanÄke" "$TmpDir/pki-user-show-ca-001_56_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_show-CA-045: userid with i18n characters"
        rlLog "user-add userid ÉricTêko with i18n characters"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-add --fullName=test 'ÉricTêko' > $TmpDir/pki-user-show-ca-001_57.out 2>&1" \
                    0 \
                    "Adding user id ÉricTêko with i18n characters"
	rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show 'ÉricTêko'"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    user-show 'ÉricTêko' > $TmpDir/pki-user-show-ca-001_57_2.out" \
                    0 \
                    "Show user 'ÉricTêko'"
        rlAssertGrep "User \"ÉricTêko\"" "$TmpDir/pki-user-show-ca-001_57_2.out"
        rlAssertGrep "User ID: ÉricTêko" "$TmpDir/pki-user-show-ca-001_57_2.out"
    rlPhaseEnd 

    rlPhaseStartTest "pki_user_cli_user_cleanup-046: Deleting the temp directory and users"
	del_user=($CA_adminV_user $CA_adminR_user $CA_adminE_user $CA_adminUTCA_user $CA_agentV_user $CA_agentR_user $CA_agentE_user $CA_agentUTCA_user $CA_auditV_user $CA_operatorV_user)

        #===Deleting users created using CA_adminV cert===#
        i=1
        while [ $i -lt 24 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  u$i > $TmpDir/pki-user-del-ca-user-00$i.out" \
                           0 \
                           "Deleted user  u$i"
                rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-00$i.out"
                let i=$i+1
        done
        #===Deleting users(symbols) created using CA_adminV cert===#
        j=1
        while [ $j -lt 8 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done

	#===Deleting i18n users created using CA_adminV cert===#
        rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
                user-del 'ÖrjanÄke' > $TmpDir/pki-user-del-ca-user-i18n_1.out" \
                0 \
                "Deleted user ÖrjanÄke"
        rlAssertGrep "Deleted user \"ÖrjanÄke\"" "$TmpDir/pki-user-del-ca-user-i18n_1.out"

        rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
                user-del 'ÉricTêko' > $TmpDir/pki-user-del-ca-user-i18n_2.out" \
                0 \
                "Deleted user ÉricTêko"
        rlAssertGrep "Deleted user \"ÉricTêko\"" "$TmpDir/pki-user-del-ca-user-i18n_2.out"

	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}