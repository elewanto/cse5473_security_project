#!/bin/bash

# Team Password is Password
# CSE 5473 MitM Project

# if editing in Windows, can use vim to convert to Unix endings:
#1. :set fileformat=unix
#2  :wq!

# use locally installed deprecated Python 2.7.9
#/usr/local/python2.7.9/bin/python2.7 /usr/local/python2.7.9/bin/tls.py server -k ~/Desktop/tlslite-ng-master/tests/serverX509Key.pem -c ~/Desktop/tlslite-ng-master/tests/serverX509Cert.pem localhost:4443

/usr/local/python2.7.9/bin/python2.7 /media/sf_cse5473_security_project/poodle-files/poodle-eric/tlslite-ng-master/scripts/tls.py server -k /media/sf_cse5473_security_project/poodle-files/poodle-eric/tlslite-ng-master/tests/serverX509Key.pem -c /media/sf_cse5473_security_project/poodle-files/poodle-eric/tlslite-ng-master/tests/serverX509Cert.pem localhost:4443

