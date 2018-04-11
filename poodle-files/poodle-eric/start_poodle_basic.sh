#!/bin/bash

# Team Password is Password
# CSE 5473 MitM Project

# if editing in Windows, can use vim to convert to Unix endings:
#1. :set fileformat=unix
#2  :wq!

# use locally installed deprecated Python 2.7.9
/usr/local/python2.7.9/bin/python2.7 poodle_basic.py 'Cookie: supersecrettoken'
