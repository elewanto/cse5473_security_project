#!/bin/bash

# Team Password is Password
# CSE 5473 MitM Project

# if editing in Windows, can use vim to convert to Unix endings:
#1. :set fileformat=unix
#2  :wq!

# poodle_attack.py programmed with Python 2.7.9


# python poodle_attack.py -server <IP> <Port> <Delay(uSec)>
#python poodle_attack.py -server 127.0.0.1 11111 15000

python poodle_attack.py -server 10.0.2.4 11111 150000
