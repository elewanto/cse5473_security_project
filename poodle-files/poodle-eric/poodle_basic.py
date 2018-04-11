# CSE 5473
# Team Password is Pasword
# Program: base program called from shell script
# Resources: uses the following resources:
#   Padding Oracle Attack Lab approach
#   "This POODLE Bites: Exploiting the SSL 3.0 Fallback" (Google Security Bulletin)
#   "Here Come the XOR Ninjas" [BEAST Attack]
#   "ImperialViolet - POODLE attacks on SSLv3 (14 Oct 2014)""

# Written for deprecated Python 2.7.9 and OpenSSL 1.0.2a implementations that supported SSLv3 protcol:
# Simulating OpenSSL ssl3 AES-128-CBC-SHA
# Uses Crypto.Cipher AES-128 CBC mode
# SSLv3 uses HMAC-SHA1 algorithm for MAC
# Crypto.Cipher AES-128 requires 128-bit key (16 byte)
# AES CBC mode uses 16 byte block-size
# AES CBC requires a randomized IV
# For POODLE attack, IV needs to be re-randomized each simulated HTTPS request from victim to server, so that the 
# data blocks are changed each new request, in order to allow the last byte of the data block to eventually match
# the expected padding value of 15, i.e. the value of of a 16-byte full padding block

from Crypto.Cipher import AES # AES symmetric encryption cipher (CBC mode)
import binascii               # hexadecimal string processing
import sys                    # command line arguments
import array                  
from Crypto import Random     # pycrypto module to generate strong random numbers for key and IV
from Crypto.Hash import HMAC  # for MAC calculation to append to http message before encryption
from Crypto.Hash import SHA

# global variables
AES_CBC_BLOCK_SIZE = 16               # AES block size is 16 bytes / 128 bits
keyAES = 0
plaintextCookie = 'cookie'
macLength = 20


def encryptMessage(message):
  #print '\n*** ENCRYPT ***'
  # block-sized IV randomized for each simulated HTTPS request; needs to vary for every request!!  
  IV = Random.get_random_bytes(AES_CBC_BLOCK_SIZE)
  #print 'IV length: ', len(IV)
  #print 'IV: ', binascii.hexlify(IV)
  cipher = AES.new(keyAES, AES.MODE_CBC, IV)
  C0 = IV
  C1toCn = cipher.encrypt(message)
  #print 'IV concat w/ encrypt message length: ', len(C1toCn)
  #print 'IV concat w/ encrypt message: ', binascii.hexlify(C1toCn)  
  encryptMessage = C0 + C1toCn
  #print 'IV concat w/ encrypt message length: ', len(encryptMessage)
  #print 'IV concat w/ encrypt message: ', binascii.hexlify(encryptMessage)

  return encryptMessage


# macLength should always be 20 bytes
# return: 1 on successful decrypt
# return: -1 on padding error
# return: -2 on MAC error
def decryptMessage(encryptMessage):
 # print '\n*** DECRYPT ***'
  # remove IV from first 16 bytes of message
  IV = encryptMessage[:AES_CBC_BLOCK_SIZE]
#  print 'IV length: ', len(IV)
#  print 'IV: ', binascii.hexlify(IV)
  # discard IV from message
  encryptMessage = encryptMessage[AES_CBC_BLOCK_SIZE:]
#  print 'encrypt message length w/out IV: ', len(encryptMessage)
#  print 'encrypt message w/out IV: ', binascii.hexlify(encryptMessage)
  cipher = AES.new(keyAES, AES.MODE_CBC, IV)
  decryptMessageMacPad = cipher.decrypt(encryptMessage)
#  print 'decrypt message|MAC|pad length: ', len(decryptMessageMacPad)
#  print 'decrypt message|MAC|pad: ', binascii.hexlify(decryptMessageMacPad)

  decryptMessageMac = unpad(decryptMessageMacPad)
  if decryptMessageMac == -1:
    return -1
#    print 'Error: incorrect padding found: ', binascii.hexlify(decryptMessageMacPad[len(decryptMessageMacPad)-1:])

  mac = decryptMessageMac[len(decryptMessageMac) - macLength:]
  decryptMessage = decryptMessageMac[:len(decryptMessageMac) - macLength]
#  print 'decrypt message length: ', len(decryptMessage)
#  print 'decrypt message (hex): ', binascii.hexlify(decryptMessage)
#  print 'decrypt message: ', decryptMessage

  macDerived = HMAC.new(keyAES, decryptMessage, SHA)
  macDerivedTag = macDerived.digest()

#  print 'received MAC: ', binascii.hexlify(mac)
#  print 'derived MAC : ', binascii.hexlify(macDerivedTag)
  if mac != macDerivedTag:
    return -2
#    print 'Error: derived MAC does not match received MAC'
  else:
    return decryptMessage
#    print 'Success: MAC codes match'



# macLength should always be 20 bytes
# return: 1 on successful decrypt
# return: -1 on padding error
# return: -2 on MAC error
def HTTPSOracleSSL3(encryptMessage):
 # print '\n*** DECRYPT ***'
  # remove IV from first 16 bytes of message
  IV = encryptMessage[:AES_CBC_BLOCK_SIZE]
#  print 'IV length: ', len(IV)
#  print 'IV: ', binascii.hexlify(IV)
  # discard IV from message
  encryptMessage = encryptMessage[AES_CBC_BLOCK_SIZE:]
#  print 'encrypt message length w/out IV: ', len(encryptMessage)
#  print 'encrypt message w/out IV: ', binascii.hexlify(encryptMessage)
  cipher = AES.new(keyAES, AES.MODE_CBC, IV)
  decryptMessageMacPad = cipher.decrypt(encryptMessage)
#  print 'decrypt message|MAC|pad length: ', len(decryptMessageMacPad)
#  print 'decrypt message|MAC|pad: ', binascii.hexlify(decryptMessageMacPad)

  decryptMessageMac = unpad(decryptMessageMacPad)
  if decryptMessageMac == -1:
    #print 'Error: incorrect padding found: ', binascii.hexlify(decryptMessageMacPad[len(decryptMessageMacPad)-1:])    
    return -1


  mac = decryptMessageMac[len(decryptMessageMac) - macLength:]
  decryptMessage = decryptMessageMac[:len(decryptMessageMac) - macLength]
#  print 'decrypt message length: ', len(decryptMessage)
#  print 'decrypt message (hex): ', binascii.hexlify(decryptMessage)
#  print 'decrypt message: ', decryptMessage

  macDerived = HMAC.new(keyAES, decryptMessage, SHA)
  macDerivedTag = macDerived.digest()

#  print 'received MAC: ', binascii.hexlify(mac)
#  print 'derived MAC : ', binascii.hexlify(macDerivedTag)
  if mac != macDerivedTag:
    #print 'Error: derived MAC does not match received MAC'    
    return -2

  else:
    return 1
#    print 'Success: MAC codes match'



def unpad(message):
  #print '\n*** UNPAD ***'
  padByte = message[len(message)-1:]
  # remove last pad byte from message
  message = message[:len(message)-1]
#  print 'message minus last pad byte length: ', len(message)
#  print 'message minus last pad byte (hex): ', binascii.hexlify(message)
#  print 'padByte: ', binascii.hexlify(padByte), ', ', ord(padByte)
  if ord(padByte) < 0 or ord(padByte) > AES_CBC_BLOCK_SIZE:
#    print "Error: incorrect padding value found"
    return -1
  messageMinusPadding = message[:len(message)-ord(padByte)]
#  print 'message|MAC length after unpad: ', len(messageMinusPadding)
#  print 'message|MAC after unpad:', binascii.hexlify(messageMinusPadding)

  return messageMinusPadding



# message must be integral multiple of the 16-byte block size
# padding scheme is random bytes followed by a final integer byte indicating the number of random padding bytes
# if the message is already a multiple of the block size, a full block of padding is added to the message
def addPadding(message):
  #print '\n*** PAD ***'
  # determine number of padding bytes needed
  padLength = AES_CBC_BLOCK_SIZE - (len(message) % AES_CBC_BLOCK_SIZE)
  #print 'pad length: ', padLength

  for i in range(padLength - 1):  # add random padding bytes to end of message
    message = message + 'X'         

 # print 'final pad byte (hex): ', binascii.hexlify(binascii.a2b_qp(chr(padLength-1)))
  messagePadded = message + binascii.a2b_qp(chr(padLength-1))   # add final padding byte = number of padding bytes added
  #print 'padded message (hex): ', binascii.hexlify(messagePadded)
 # print 'padded message length: ', len(messagePadded)

  return messagePadded



# request plaintext message format 'POST /PATH Cookie:cookie_value BODY || MAC || padding'
def craftRequestMessage(pathFillBytes, plaintextCookie, bodyFillBytes):
  # add injected path text before cookie and body text after cookie
  path = '/httpsserverpage'
  body = 'body'
  message = 'POST ' + path + pathFillBytes + plaintextCookie + body + bodyFillBytes
  print 'message: ',  message
  print 'message length: ', len(message)
  print '*** MAC ***'
  # compute MAC (SHA-1 algorithm for SSLv3) and append to end of plaintext message
  mac = HMAC.new(keyAES, message, SHA)    # create pycrypto HMAC object
  macTag = mac.digest()                # returns binary HMAC tag
  print 'mac: ', binascii.hexlify(macTag)
  macLength = len(macTag)
  print 'mac length: ', len(macTag)
  # concatenate request message + MAC_tag
  messageAndMac = message + macTag
  print 'message length before padding: ', len(messageAndMac)
  # add padding to message to make multiple of 16-byte block size
  messagePadded = addPadding(messageAndMac)
  messageEncrypted = encryptMessage(messagePadded)

  messageDecrypted = decryptMessageOracle(messageEncrypted, macLength)


def victimCraftHTTPSRequest(path, pathFillBytes, body, bodyFillBytes):
  message = path + pathFillBytes + plaintextCookie + body + bodyFillBytes
  #print message
  mac = HMAC.new(keyAES, message, SHA)    # create pycrypto HMAC object
  macTag = mac.digest()                # returns binary HMAC tag
  macLength = len(macTag)
  messageAndMac = message + macTag
  messagePadded = addPadding(messageAndMac)
  messageEncrypted = encryptMessage(messagePadded)

  return messageEncrypted



def poodleAttack():
  #1. Attacker crafts HTTP message with JavaScript injection that victim will send as HTTPS reqeust
  # add initial fill bytes to end of POST path and end of body
  pathFillBytes = 'PPPPPPPPPPPPPPPPPPPP'
  bodyFillBytes = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
  path = '/httpsserverpage'
  body = 'body'
  messagePath = 'POST ' + path + pathFillBytes 
  messageBody = body + bodyFillBytes

  #2. Attacker sends modified message path, body to victim server to craft message with cookie into HTTPS request;
  #   attacker intercepts encrypted message from victim enroute to HTTPS server
  messageEncrypted = victimCraftHTTPSRequest(path, pathFillBytes, body, bodyFillBytes)
  #3. Now add more fill bytes to end of message body until the length of the intercepted message changes;
  #   then we know that the message contains a FULL PADDING BLOCK at the end
  encMessageLength = len(messageEncrypted)
  newLength = encMessageLength
  print 'length of initially filled encrypted message: ', encMessageLength
  while ( newLength == encMessageLength):
    bodyFillBytes += 'B'
    messageEncrypted = victimCraftHTTPSRequest(path, pathFillBytes, body, bodyFillBytes)
    newLength = len(messageEncrypted)

  encMessageLength = newLength
  numBlocks = encMessageLength / AES_CBC_BLOCK_SIZE
  # message is even multiple; now add 16 more fill bytes to ensure full padding block at end of message
  print 'length of adjusted filled encrypted message: ', encMessageLength
  print 'number of message blocks', numBlocks

  # decide starting block to decrypt (offset at least three blocks so avoid MAC|padding)
  i = 5
  if i < 1:
    print 'Error: not enough blocks in cipher message to decrypt'
  numBytesToDecrypt = i*AES_CBC_BLOCK_SIZE - AES_CBC_BLOCK_SIZE
  print 'Number bytes to decrypt: ', numBytesToDecrypt
  numDecryptedBytes = 0
  decryptSuccess = 0
  attempts = 0
  #4. start with Ci and position and overwrite end padding block
  for k in range(0, numBytesToDecrypt):
    while (decryptSuccess != 1):
      messageEncrypted = victimCraftHTTPSRequest(path, pathFillBytes, body, bodyFillBytes)  
      CiBlock = messageEncrypted[i * AES_CBC_BLOCK_SIZE : (i*AES_CBC_BLOCK_SIZE) + AES_CBC_BLOCK_SIZE]
      messageEncrypted = messageEncrypted[:len(messageEncrypted) - AES_CBC_BLOCK_SIZE]
      messageEncrypted = messageEncrypted + CiBlock
      decryptSuccess = HTTPSOracleSSL3(messageEncrypted)
      attempts += 1

    start = (i * AES_CBC_BLOCK_SIZE) - 1
    CiMinusOneByte = messageEncrypted[start:start+1]
    start = ((numBlocks - 1) * AES_CBC_BLOCK_SIZE) - 1
    CnMinusOneByte = messageEncrypted[start:start+1]

    PiByte = (15 ^ ord(CiMinusOneByte)) ^ ord(CnMinusOneByte)
    print PiByte, binascii.b2a_qp(chr(PiByte))

    attempts = 0
    decryptSuccess = 0
    pathFillBytes += 'P'  # add char to path fill bytes to shift bytes right
    bodyFillBytes = bodyFillBytes[1:] # remove one char from body fill bytes to keep full padding block





if __name__ == '__main__':

  plaintextCookie = sys.argv[1]   # get token from command line
  #print plaintextCookie


  # need key...can stay the same or randomize to simulate changing sessions
  keyAES = Random.get_random_bytes(AES_CBC_BLOCK_SIZE)
  print 'keylength: ', len(keyAES)
  print 'key: ', binascii.hexlify(keyAES)     # show hex representation of binary data

  #craftRequestMessage(pathFillBytes, plaintextCookie, bodyFillBytes)

  poodleAttack()