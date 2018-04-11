# Bleichenbacher Attack Notes


Running the Server
-----------------------

Which IDE to USE


[Download Pycharm community Edition](https://www.jetbrains.com/pycharm/download/)

How to run the server
----------------------

simply from terminal


server -k "../tests/serverX509Key.pem" -c "../tests/serverX509Cert.pem" -t "../tests/TACK1.pem" 10.1.2.5:443


Changed in handshakesettings.py

    if other.minKeySize < 128:
        raise ValueError("minKeySize too small")


    settings.minKeySize = 128
    settings.maxKeySize = 128
    settings.cipherNames = ['aes128']
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    settings.useExperimentalTackExtension=False
    settings.macNames = ['md5']
    settings.useExtendedMasterSecret = False









Add to documents 
change cache bits
browser.cache.memory.enable;false
browser.cache.disk.enable;false




RSA example
https://www.devco.net/archives/2006/02/13/public_-_private_key_encryption_using_openssl.php


secret = bytearray(b'\x03\x00\n\xbf&#;\xc3\xe9\x84\x01\xceKz\xaf\\\xff\'\xec\xcaUb\x9e\xc5\x95\xd1\xa2\x11!\xe1\x15\xfe"\x18\x19\x9a\xf1*\x1a\xa8d\xdd\xa6\x7f\xfd\x16L\xfa')
seed = bytearray(b'\x9e\xfa\x10\xd1\xcfId\x0co6\x14A!\x17`\xe6\x1b\xf9Xw[\xa5o/\x18R\xa7\xe7\xc8\x84\xe7f\xc1\x15\xd2\xfe\xc7\xfe\x16\x1b7\xb7\xd6\xfe\x15Q\x04\x9e_Q\xf9h\xd7\xcb\x0b\xfb_;z7\x1d\xdc\xef\x8c')
length = 48
def PRF_SSL(secret, seed, length):
    bytes = bytearray(length)
    index = 0
    for x in range(26):
        A = bytearray([ord('A')+x] * (x+1)) # 'A', 'BB', 'CCC', etc..
        input = secret + SHA1(A + secret + seed)
        output = MD5(input)
        for c in output:
            if index >= length:
                return bytes
            bytes[index] = c
            index += 1
    return bytes



"secret= ["+" ".join("{:02x}".format(x) for x in secret)+"]"

"premasterSecret= ["+" ".join("{:02x}".format(x) for x in premasterSecret)+"]" 


'premasterSecret= [03 00 4b 17 4b 32 c5 ef da 24 1e 2d 42 d1 66 93 c9 90 ec 72 25 d4 71 20 2e db 83 50 e8 b1 30 df ae b2 56 44 97 8f 7e 98 e5 98 56 16 08 01 dc 4e]'


"clientKeyExchange.encryptedPreMasterSecret= ["+" ".join("{:02x}".format(x) for x in clientKeyExchange.encryptedPreMasterSecret)+"]" 

clientKeyExchange.encryptedPreMasterSecret= [77 9f 65 c6 ca e8 b6 49 df 83 a0 6b 6d b9 df a0 45 6f 41 61 91 b4 b3 4a df 30 60 7a cd 0c bd 1b e7 e7 ed 9d f4 0d 2a 89 04 c6 98 22 10 2d 56 cc 13 74 89 31 16 0d c9 fd 00 3e 26 62 05 b6 71 68 01 c0 82 ed 1f 99 77 59 aa b5 70 44 95 10 f0 52 06 b4 4f 31 21 ab 0f 82 2c 1a df 54 0c a5 f4 38 59 ee b6 de 18 8c e7 2b b8 c5 5b 62 9c b0 59 33 41 b2 7c 54 4f ae ae 06 96 7c a0 0a 19 bb 5f e4 38 b4 11 fe 3d 55 5e 63 a4 8f a9 6b b2 05 b4 62 d2 f0 3e 56 63 ef d2 f8 bc 25 2f 0d 8c a8 59 97 77 6c 92 a4 e2 81 5c 47 98 8b 6d 30 90 a0 d6 d6 59 7b 11 c7 13 9e ea 70 7f 71 b9 5f 38 2f 8f a4 4e 00 72 eb e1 da 04 9e b3 c7 fb 1c 9c 05 5e c5 fa 5c f8 33 f6 54 ea 81 e6 ff d0 0c db 83 5a bf 5a 35 8b 30 a1 7b 7e d7 4e 55 8a 81 d3 35 1a e4 07 c1 41 77 5f a2 3e c2 6d 59 b3 b7 11 28 40 4e]


# In Wireshark
0000   77 9f 65 c6 ca e8 b6 49 df 83 a0 6b 6d b9 df a0  w.e....I...km...
0010   45 6f 41 61 91 b4 b3 4a df 30 60 7a cd 0c bd 1b  EoAa...J.0`z....
0020   e7 e7 ed 9d f4 0d 2a 89 04 c6 98 22 10 2d 56 cc  ......*....".-V.
0030   13 74 89 31 16 0d c9 fd 00 3e 26 62 05 b6 71 68  .t.1.....>&b..qh
0040   01 c0 82 ed 1f 99 77 59 aa b5 70 44 95 10 f0 52  ......wY..pD...R
0050   06 b4 4f 31 21 ab 0f 82 2c 1a df 54 0c a5 f4 38  ..O1!...,..T...8
0060   59 ee b6 de 18 8c e7 2b b8 c5 5b 62 9c b0 59 33  Y......+..[b..Y3
0070   41 b2 7c 54 4f ae ae 06 96 7c a0 0a 19 bb 5f e4  A.|TO....|...._.
0080   38 b4 11 fe 3d 55 5e 63 a4 8f a9 6b b2 05 b4 62  8...=U^c...k...b
0090   d2 f0 3e 56 63 ef d2 f8 bc 25 2f 0d 8c a8 59 97  ..>Vc....%/...Y.
00a0   77 6c 92 a4 e2 81 5c 47 98 8b 6d 30 90 a0 d6 d6  wl....\G..m0....
00b0   59 7b 11 c7 13 9e ea 70 7f 71 b9 5f 38 2f 8f a4  Y{.....p.q._8/..
00c0   4e 00 72 eb e1 da 04 9e b3 c7 fb 1c 9c 05 5e c5  N.r...........^.
00d0   fa 5c f8 33 f6 54 ea 81 e6 ff d0 0c db 83 5a bf  .\.3.T........Z.
00e0   5a 35 8b 30 a1 7b 7e d7 4e 55 8a 81 d3 35 1a e4  Z5.0.{~.NU...5..
00f0   07 c1 41 77 5f a2 3e c2 6d 59 b3 b7 11 28 40 4e  ..Aw_.>.mY...(@N


