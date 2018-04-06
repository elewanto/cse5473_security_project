# CSE 5473
# Team Password is Pasword
# Program: base program called from shell script
# Resources: uses the following resources:
#   Padding Oracle Attack Lab approach
#   "This POODLE Bites: Exploiting the SSL 3.0 Fallback" (Google Security Bulletin)
#   "Here Come the XOR Ninjas" [BEAST Attack]

# Written for deprecated Python 2.7.9 and OpenSSL 1.0.2a implementations that supported SSLv3 protcol:

from Crypto.Cipher import AES # AES symmetric encryption cipher (CBC mode)
import binascii               # hexadecimal string processing
import sys                    # command line arguments
import array                  

# global variables
BLOCK_SIZE = 16   # AES block size is 16 bytes / 128 bits




print 'test success'


