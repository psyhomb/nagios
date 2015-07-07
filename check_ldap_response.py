#!/usr/bin/env python2
# Author: Milos Buncic
# Date: 2015-07-02
# Description: Nagios - check if LDAP is responding to request
# Dependencies: ldapsearch

import os
import sys
import time
import subprocess
import shlex
import optparse


# Default vars (can be overridden by a command line args) 
hostname = 'ldap.example.com'
protocol = 'ldaps'
port = '636'
username = 'test'

# Default search vars (cannot be overridden by a command line args)
# Note: %s in binddn will be replaced with username
binddn = 'cn=%s,ou=machines,dc=example,dc=com'
searchbase = 'ou=people,dc=example,dc=com'
filter = 'ou=people'

# LDAP CA certificate path (used if protocol is set to ldaps)
cacert = '/etc/openldap/cacerts/ca.pem'


def argsParser():
    """ Return options collected from cmd line (output: dict) """
    parser = optparse.OptionParser()
    parser.add_option('-T', '--protocol', help='LDAP type [Default: %default]', default=protocol, dest='protocol', action='store')
    parser.add_option('-H', '--hostname', help='LDAP server hostname [Default: %default]', default=hostname, dest='hostname', action='store')
    parser.add_option('-P', '--port', help='LDAP port [Default: %default]', default=port, dest='port', action='store')
    parser.add_option('-u', '--username', help='LDAP user with appropriate permissions [Default: %default]', default=username, dest='username', action='store')
    parser.add_option('-p', '--password', help='LDAP user\'s password', default=None, dest='password', action='store')

    opts, args = parser.parse_args()
    opts = opts.__dict__

    return opts


def cmd(command_line):
    """ Return output of a system command (output: dict) """
    process = subprocess.Popen(shlex.split(command_line), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return {'output': output, 'error': error, 'code': process.returncode}


def ldapRequest(ldap_opts):
    """ Return output of ldapsearch (output: tuple) """
    start = time.time() * 1000
    output = cmd('/usr/bin/ldapsearch -H "%(protocol)s://%(hostname)s:%(port)s" -D %(username)s %(password)s -b %(searchbase)s -LLL -x %(filter)s' % ldap_opts)
    now = time.time() * 1000
    rtime = now - start
    return output['output'], output['error'], output['code'], rtime


try:
    opts = argsParser()

    # Add extra elements into dict 
    opts['username'] = binddn % opts['username']
    opts['searchbase'] = searchbase
    opts['filter'] = filter

    # Check if password is specified
    if opts['password']:
        opts['password'] = '-w ' + opts['password']
    else:
        opts['password'] = '-W'

    # Set env var for CA certificate
    if opts['protocol'] == 'ldaps':
        os.environ['LDAPTLS_CACERT'] = cacert
except SystemExit:
    sys.exit(3)

response = ldapRequest(opts)

output = response[0].strip().replace('\n', ' ')
error = response[1].strip().replace('\n', ' ')
code = response[2]
rtime = response[3]

if code == 0:
    print "OK: Valid response received from %s (%s) | response_time=%0.2f" % (opts['hostname'], output, rtime)
    sys.exit(0)
else:
    print "CRITICAL: %s - %s | response_time=%0.2f" % (opts['hostname'], error, rtime)
    sys.exit(2)
