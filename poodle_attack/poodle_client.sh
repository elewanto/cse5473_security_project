#!/bin/bash

# Team Password is Password
# CSE 5473 MitM Project

# if editing in Windows, can use vim to convert to Unix endings:
#1. :set fileformat=unix
#2  :wq!


# python poodle_attack.py -client <IP> <Port> <token-value> <record-splitting:True/False>

#python poodle_attack.py -client 127.0.0.1 11111 SquirrelTeamSix False

#python poodle_attack.py -client 127.0.0.1 11111 SquirrelTeamSix True


python poodle_attack.py -client 10.0.2.4 11111 SquirrelTeamSix False

#python poodle_attack.py -client 10.0.2.4 11111 SquirrelTeamSix True