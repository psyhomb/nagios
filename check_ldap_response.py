#!/usr/bin/env python2
# Author: Milos Buncic
# Date: 2015-07-02
# Description: Nagios - check if LDAP is responding to request
# Dependencies: ldapsearch

import os
import sys
import subprocess
import shlex
import optparse


# Default vars (can be overridden by a command line args) 
hostname = 'ldap.example.com'
protocol = 'ldaps'
port = '636'
username = 'test'

# Default search vars (cannot be overridden by a command line args)
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
    output = cmd('/usr/bin/ldapsearch -H "%(protocol)s://%(hostname)s:%(port)s" -D "cn=%(username)s,ou=machines,dc=example,dc=com" %(password)s -b %(searchbase)s -LLL -x %(filter)s' % ldap_opts)
    return output['output'], output['error'], output['code']


try:
    opts = argsParser()

    # Add extra elements into dict 
    opts['filter'] = filter
    opts['searchbase'] = searchbase

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

output = response[0].strip()
error = response[1].strip()
code = response[2]

if code == 0:
    print "OK: Valid response received from %s\n\n%s" % (opts['hostname'], output)
    sys.exit(0)
else:
    print "CRITICAL: Invalid or no response received from %s\n%s" % (opts['hostname'], error)
    sys.exit(2)
