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
from Crypto import Random     # pycrypto module to generate strong random numbers for key and IV
from Crypto.Hash import HMAC  # for MAC calculation to append to http message before encryption
from Crypto.Hash import SHA   # HMAC functionality
import socket                 # socket communications
import time                   # time delays
import curses                 # bash graphics
from curses import wrapper
import os                     # system sounds

# global variables
AES_CBC_BLOCK_SIZE = 16               # AES block size is 16 bytes / 128 bits
keyAES = ''                           # AES key
plaintextCookie = 'Cookie'            # secure cookie contents
macLength = 20                        # length of MAC tag
buffsize = 512                        # socket buffer size
recordSplit = False                   # use record splitting defense
delay = 10000
screen = ''
topWin = ''
middleWin = ''
bottomWin = ''
height = 0
width = 0


def encryptMessage(message):

  #print '\n*** ENCRYPT ***'
  # block-sized IV randomized for each simulated HTTPS request; needs to vary for every request!!  
  IV = Random.get_random_bytes(AES_CBC_BLOCK_SIZE)
  cipher = AES.new(keyAES, AES.MODE_CBC, IV)
  C0 = IV
  C1toCn = cipher.encrypt(message)
  encryptMessage = C0 + C1toCn

  return encryptMessage


# macLength should always be 20 bytes
# return: 1 on successful decrypt
# return: -1 on padding error
# return: -2 on MAC error
def decryptMessage(encryptMessage):
  # remove IV from first 16 bytes of message
  IV = encryptMessage[:AES_CBC_BLOCK_SIZE]
  # discard IV from message
  encryptMessage = encryptMessage[AES_CBC_BLOCK_SIZE:]
  cipher = AES.new(keyAES, AES.MODE_CBC, IV)
  decryptMessageMacPad = cipher.decrypt(encryptMessage)
  decryptMessageMac = unpad(decryptMessageMacPad)
  if decryptMessageMac == -1:
    return -1
  mac = decryptMessageMac[len(decryptMessageMac) - macLength:]
  decryptMessage = decryptMessageMac[:len(decryptMessageMac) - macLength]
  macDerived = HMAC.new(keyAES, decryptMessage, SHA)
  macDerivedTag = macDerived.digest()
  if mac != macDerivedTag:
    return -2
  else:
    return decryptMessage



# macLength should always be 20 bytes
# return: 1 on successful decrypt
# return: -1 on padding error
# return: -2 on MAC error
def HTTPSOracleSSL3(encryptMessage):
  # remove IV from first 16 bytes of message
  IV = encryptMessage[:AES_CBC_BLOCK_SIZE]
  if len(IV) != 16:
    return -3
  # discard IV from message
  encryptMessage = encryptMessage[AES_CBC_BLOCK_SIZE:]
  cipher = AES.new(keyAES, AES.MODE_CBC, IV)
  decryptMessageMacPad = cipher.decrypt(encryptMessage)
  decryptMessageMac = unpad(decryptMessageMacPad)
  if decryptMessageMac == -1:
    return -1
  mac = decryptMessageMac[len(decryptMessageMac) - macLength:]
  decryptMessage = decryptMessageMac[:len(decryptMessageMac) - macLength]
  macDerived = HMAC.new(keyAES, decryptMessage, SHA)
  macDerivedTag = macDerived.digest()
  if mac != macDerivedTag:
    return -2
  else:
    return 1



def unpad(message):
  padByte = message[len(message)-1:]
  # remove last pad byte from message
  message = message[:len(message)-1]

  if ord(padByte) < 0 or ord(padByte) > AES_CBC_BLOCK_SIZE:
    return -1
  messageMinusPadding = message[:len(message)-ord(padByte)]
  return messageMinusPadding



# message must be integral multiple of the 16-byte block size
# padding scheme is random bytes followed by a final integer byte indicating the number of random padding bytes
# if the message is already a multiple of the block size, a full block of padding is added to the message
def addPadding(message):
  # determine number of padding bytes needed
  padLength = AES_CBC_BLOCK_SIZE - (len(message) % AES_CBC_BLOCK_SIZE)
  for i in range(padLength - 1):  # add random padding bytes to end of message
    message = message + 'X'         
  messagePadded = message + binascii.a2b_qp(chr(padLength-1))   # add final padding byte = number of padding bytes added
  return messagePadded



def victimCraftHTTPSRequest(path, pathFillBytes, body, bodyFillBytes):
  global macLength

  message = path + pathFillBytes + plaintextCookie + body + bodyFillBytes
  if recordSplit and ((len(message) + macLength) % AES_CBC_BLOCK_SIZE == 0):
    recordSplitting()
  mac = HMAC.new(keyAES, message, SHA)    # create pycrypto HMAC object
  macTag = mac.digest()                # returns binary HMAC tag
  macLength = len(macTag)
  messageAndMac = message + macTag
  messagePadded = addPadding(messageAndMac)
  messageEncrypted = encryptMessage(messagePadded)

  return messageEncrypted


# 8/n-8 record splitting as defense against POODLE attack
def recordSplitting():
  bottomWin.addstr('Splitting record 8 / n-8\n')
  bottomWin.refresh()
  return



def poodleAttack(clientServerSocket):
  #1. Attacker crafts HTTP message with JavaScript injection that victim will send as HTTPS reqeust
  # add initial fill bytes to end of POST path and end of body
  pathFillBytes = 'PPPP'
  bodyFillBytes = 'B'
  path = '/https_page'
  body = '_body_'
  messagePath = 'POST ' + path + pathFillBytes 
  messageBody = body + bodyFillBytes

  #2. Attacker sends modified message path, body to victim server to craft message with cookie into HTTPS request;
  #   attacker intercepts encrypted message from victim enroute to HTTPS server
  messageEncrypted = victimCraftHTTPSRequest(path, pathFillBytes, body, bodyFillBytes)
  #3. Now add more fill bytes to end of message body until the length of the intercepted message changes;
  #   then we know that the message contains a FULL PADDING BLOCK at the end
  encMessageLength = len(messageEncrypted)
  newLength = encMessageLength
  bottomWin.addstr('length of initially filled encrypted message: ' + str(encMessageLength) + '\n')
  bottomWin.refresh()
  while (newLength == encMessageLength):
    bodyFillBytes += 'B'
    messageEncrypted = victimCraftHTTPSRequest(path, pathFillBytes, body, bodyFillBytes)
    newLength = len(messageEncrypted)
  encMessageLength = newLength
  numBlocks = encMessageLength / AES_CBC_BLOCK_SIZE
  # message is even multiple; now add 16 more fill bytes to ensure full padding block at end of message
  bottomWin.addstr('length of adjusted filled encrypted message: ' + str(encMessageLength) +'\n')
  bottomWin.addstr('number of message blocks: ' + str(numBlocks) + '\n')
  # decide starting block to decrypt (offset at least three blocks so avoid MAC|padding)
  i = 3
  if i < 1:
    bottomWin.addstr('Error: not enough blocks in cipher message to decrypt\n')
    bottomWin.refresh()
  numBytesToDecrypt = i*AES_CBC_BLOCK_SIZE - AES_CBC_BLOCK_SIZE
  bottomWin.addstr('Number bytes to decrypt: ' + str(numBytesToDecrypt) + '\n')
  bottomWin.addstr('...press key to continue...')
  bottomWin.refresh()
  screen.nodelay(0)
  screen.getch()
  screen.nodelay(1)
  bottomWin.erase()
  bottomWin.refresh()

  numDecryptedBytes = 0
  serverResponse = 0
  attempts = 0
  #4. start with Ci and position and overwrite end padding block
  for k in range(0, numBytesToDecrypt):
    while (serverResponse != 1):
      if screen.getch() == ord('q'):
        closeScreen()
        clientServerSocket.close()
        sys.exit()
      topWin.erase()
      topWin.addstr(0, 0, 'CLIENT BROWSER')
      topWin.addstr(0, 40, 'Secret:')
      topWin.addstr(0, 48, plaintextCookie, curses.color_pair(10))
      topWin.addstr(4, 2, path + pathFillBytes + plaintextCookie + body + bodyFillBytes)
      topWin.refresh()
      messageEncrypted = victimCraftHTTPSRequest(path, pathFillBytes, body, bodyFillBytes)
      CiBlock = messageEncrypted[i * AES_CBC_BLOCK_SIZE : (i*AES_CBC_BLOCK_SIZE) + AES_CBC_BLOCK_SIZE]
      messageEncrypted = messageEncrypted[:len(messageEncrypted) - AES_CBC_BLOCK_SIZE]
      messageEncrypted = messageEncrypted + CiBlock
      # client transmits encrypted message to HTTPS server
      if clientServerSocket.send(messageEncrypted) == 0:
        bottomWin.addstr('0 bytes sent to server socket; exiting\n')
        bottomWin.refresh()
        closeScreen()
        clientServerSocket.close()
        sys.exit()
      # client waits for response from server
      try:
        serverResponse = clientServerSocket.recv(buffsize)
      except socket.error, e: # recv error occurred
        closeScreen()
        clientServerSocket.close()
        sys.exit()        
      else:
        serverResponse = int(serverResponse)
        attempts += 1
    start = (i * AES_CBC_BLOCK_SIZE) - 1
    CiMinusOneByte = messageEncrypted[start:start+1]
    start = ((numBlocks - 1) * AES_CBC_BLOCK_SIZE) - 1
    CnMinusOneByte = messageEncrypted[start:start+1]
    PiByte = (15 ^ ord(CiMinusOneByte)) ^ ord(CnMinusOneByte)
    bottomWin.addstr(str(PiByte) + ' ' + str(binascii.b2a_qp(chr(PiByte))) + ' ' + str(attempts) + '\n')
    bottomWin.refresh()
    os.system("/usr/bin/canberra-gtk-play --id='complete-scan'") #chime
    attempts = 0
    serverResponse = 0
    pathFillBytes += 'P'  # add char to path fill bytes to shift bytes right
    if len(bodyFillBytes) > 0:
      bodyFillBytes = bodyFillBytes[1:] # remove one char from body fill bytes to keep full padding block
    else:
      if len(body) > 0:
        body = body[:len(body)-1]
      else:
        pathFillBytes = pathFillBytes[1:]



def startServer(ip, port):
  global keyAES
  global delay
  totReq = 0
  padErr = 0
  macErr = 0
  numSuc = 0

  bottomWin.addstr('Starting server...\n')
  bottomWin.refresh()
  addr = (ip, port)

  serverListen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  serverListen.bind(addr)
  serverListen.listen(5)    # param: backlog queue
  bottomWin.addstr('Server listening for connection...\n')
  bottomWin.refresh()
  while True:
    if screen.getch() == ord('q'):
      closeScreen()
      serverClientSocket.close()
      sys.exit()
    serverClientSocket, addr = serverListen.accept()
    bottomWin.addstr('Client connected IP: ' + addr[0] + '  Port: ' + str(addr[1]) + '\n')
    bottomWin.refresh()
    # first client transmission is shared AES key
    receive_data = serverClientSocket.recv(buffsize)
    bottomWin.addstr('server received session key: ' + binascii.hexlify(receive_data) + '\n')
    bottomWin.refresh()
    keyAES = receive_data
    # run until client socket closes
    while len(receive_data) > 0:
      if screen.getch() == ord('q'):
        closeScreen()
        serverClientSocket.close()
        sys.exit()
      if screen.getch() == ord('w'):
        delay += 20000
        topWin.erase()
        topWin.addstr(1, width/2 - 9, "ORACLE HTTPS SERVER")        
        topWin.addstr(1,width-3,str(delay/20000), curses.color_pair(8))
        topWin.refresh()
      if screen.getch() == ord('s'):
        if delay >= 20000:
          delay -= 20000
          topWin.erase()
          topWin.addstr(1, width/2 - 9, "ORACLE HTTPS SERVER")          
          topWin.addstr(1,width-3,str(delay/20000), curses.color_pair(8))
          topWin.refresh()
      if screen.getch() == ord('p'):
        screen.nodelay(0) 
        while screen.getch() != ord('p'):
          time.sleep(.1)
        screen.nodelay(1)
      receive_data = serverClientSocket.recv(buffsize)
      totReq += 1
      # send data to oracle to check for padding or MAC errors
      decryptSuccess = HTTPSOracleSSL3(receive_data)
      if decryptSuccess == 1:
        numSuc += 1
        bottomWin.addstr('oracle success\n', curses.color_pair(9))        
      elif decryptSuccess == -1:
        padErr += 1
        bottomWin.addstr('padding error\n', curses.color_pair(10))           
      else:
        macErr += 1
        bottomWin.addstr('MAC error\n', curses.color_pair(11))
      bottomWin.refresh()        
      updateServerStats(totReq, numSuc, padErr, macErr)
      serverClientSocket.send(str(decryptSuccess))
      time.sleep(delay / 1000000.0)      # delay between receives if want to slow down process for better visualization
    serverClientSocket.close()
    bottomWin.addstr('Server socket closed\n')
    bottomWin.refresh()
    closeScreen()



def updateServerStats(reqs, numSuc, padErr, macErr):

  middleWin.erase()  

  middleWin.addstr(0, 0, 'TOTAL REQUESTS:')
  middleWin.addstr(0, 40, 'CORRECT REQUESTS:')
  middleWin.addstr(2, 0, 'PADDING ERRORS: ')
  middleWin.addstr(2, 40, 'MAC ERRORS: ')

  middleWin.addstr(0, 16, str(reqs), curses.color_pair(4))
  middleWin.addstr(0, 58, str(numSuc) + ' / ' + '%.2f' %(100* numSuc / float(reqs)) + '%', curses.color_pair(7))
  middleWin.addstr(2, 16, str(padErr) + ' / ' + '%.2f' %(100* padErr / float(reqs)) + '%', curses.color_pair(6))
  middleWin.addstr(2, 58, str(macErr) + ' / ' + '%.2f' %(100* macErr / float(reqs)) + '%', curses.color_pair(7))

  middleWin.refresh()




def startClient(ip, port):
  global keyAES

  # get session key: this will be shared with server once for duration of the "session"
  # need key...can stay the same or randomize to simulate changing sessions
  keyAES = Random.get_random_bytes(AES_CBC_BLOCK_SIZE)
  #pstring = 'key length: ' + 
  bottomWin.addstr('key length: ' + str(len(keyAES)) + '\n')  
  bottomWin.addstr('key: '+ binascii.hexlify(keyAES) + '\n')     # show hex representation of binary data
  addr = (ip, port)
  clientServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  clientServerSocket.connect(addr)
  clientServerSocket.send(keyAES)
  bottomWin.addstr('exchanged key with Server\n')
  bottomWin.refresh()
  poodleAttack(clientServerSocket)
  clientServerSocket.close()
  closeScreen()



def setScreenClient(stdscr, ip, port):
  global screen
  global topWin
  global middleWin
  global bottomWin
  global height
  global width

  screen = curses.initscr()
  screen.nodelay(1)   # set nonblocking keyboard input
  screen.scrollok(1)
  curses.curs_set(0)  

  height, width = screen.getmaxyx()
  topWin = curses.newwin(height/2-1, width, 0, 0)
  middleWin = curses.newwin(1, width, height/2-1, 0)
  bottomWin = curses.newwin(height/2, width, height/2, 0)

  curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
  curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_YELLOW)
  curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_GREEN)
  curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_WHITE)
  curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_WHITE) 
  curses.init_pair(6, curses.COLOR_RED, curses.COLOR_WHITE)  
  curses.init_pair(7, curses.COLOR_GREEN, curses.COLOR_WHITE)   
  curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_BLACK)
  curses.init_pair(9, curses.COLOR_GREEN, curses.COLOR_BLACK)
  curses.init_pair(10, curses.COLOR_RED, curses.COLOR_BLACK)
  curses.init_pair(11, curses.COLOR_YELLOW, curses.COLOR_BLACK)

  topWin.scrollok(1)
  middleWin.scrollok(1)
  bottomWin.scrollok(1)

  topWin.addstr(0, 0, 'CLIENT BROWSER')
  topWin.addstr(0, 40, 'Secret:')
  topWin.addstr(0, 48, plaintextCookie, curses.color_pair(10))
  middleWin.addstr(0,0,"ATTACK PROGRESS")
  middleWin.bkgd(' ', curses.color_pair(4))  
  topWin.refresh()
  middleWin.refresh()
  bottomWin.refresh()
  startClient(ip, port)  



def setScreenServer(stdscr, ip, port):
  global screen
  global topWin
  global middleWin
  global bottomWin
  global height
  global width

  screen = curses.initscr()
  screen.nodelay(1)   # set nonblocking keyboard input
  screen.scrollok(1)
  curses.curs_set(0)

  height, width = screen.getmaxyx()
  topWin = curses.newwin(2, width, 0, 0) 
  middleWin = curses.newwin(3, width, 2, 0)
  bottomWin = curses.newwin(height-5, width, 5, 0)

  curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
  curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_YELLOW)
  curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_GREEN)
  curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_WHITE)
  curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_WHITE) 
  curses.init_pair(6, curses.COLOR_RED, curses.COLOR_WHITE)  
  curses.init_pair(7, curses.COLOR_GREEN, curses.COLOR_WHITE)   
  curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_BLACK)
  curses.init_pair(9, curses.COLOR_GREEN, curses.COLOR_BLACK)
  curses.init_pair(10, curses.COLOR_RED, curses.COLOR_BLACK)
  curses.init_pair(11, curses.COLOR_YELLOW, curses.COLOR_BLACK)    

  topWin.scrollok(1)
  middleWin.scrollok(1)
  bottomWin.scrollok(1) 

  #middleWin.attrset(curses.color_pair(4)) 

  topWin.addstr(1, width/2 - 9, "ORACLE HTTPS SERVER")

  middleWin.addstr(0, 0, 'TOTAL REQUESTS:')
  middleWin.addstr(0, 40, 'CORRECT REQUESTS:')
  middleWin.addstr(2, 0, 'PADDING ERRORS: ')
  middleWin.addstr(2, 40, 'MAC ERRORS: ')
  middleWin.bkgd(' ', curses.color_pair(4))
  topWin.refresh()
  middleWin.refresh()
  bottomWin.refresh()
  startServer(ip, port)  


def closeScreen():
  global screen

  curses.nocbreak()
  screen.keypad(0)
  curses.echo()
  curses.endwin()


if __name__ == '__main__':

  #os.system("/usr/bin/canberra-gtk-play --id='complete-scan'") #chime
  #os.system("/usr/bin/canberra-gtk-play --id='suspend-error'") #multiple chirps
  #os.system("/usr/bin/canberra-gtk-play --id='complete-download'") #ding

  if sys.argv[1] == '-server':
    if len(sys.argv) != 5:
      print 'poodle_basic.py -server <IP> <port> <delay>'
      print 'poodle_basic.py -client <IP> <port> <secret cookie contents> <recordSplit=True/False>'
      sys.exit(0)
    ip = sys.argv[2]
    port = int(sys.argv[3])
    delay = int(sys.argv[4])
    print 'main delay: ', delay
    wrapper(setScreenServer, ip, port)

  elif sys.argv[1] == '-client':
    if len(sys.argv) != 6:
      print 'poodle_basic.py -server <IP> <port> <delay>'
      print 'poodle_basic.py -client <IP> <port> <secret cookie contents> <recordSplit=True/False>'
      sys.exit(0)     
    ip = sys.argv[2]
    port = int(sys.argv[3])
    plaintextCookie = 'Cookie: ' + sys.argv[4]
    if sys.argv[5].lower() == 'true':
      recordSplit = True
      print 'Using 8 / (n-8) record splitting defense'
    wrapper(setScreenClient, ip, port)  
    #startClient(ip, port)

  else:
    print 'poodle_basic.py -server <IP> <port> <delay>'
    print 'poodle_basic.py -client <IP> <port> <secret cookie contents> <recordSplit=True/False>'
  