import math
def padding_oracle(c):
    hex_c= ''.join('{:02x}'.format(x) for x in c)
    if len(hex_c) > 4 and hex_c[0:4] == '0002':
        return True
    return False


# hex_data = "00 02 ab"
# hex_data = "00 02 9d b3 58 70 16 bc 0c 49 59 7e 0d a7 bd 12 5d 89 d3 d8 7b 9a 2e 6b 38 9e 03 a2 06 bd dc 60 f4 8c b5 a3 9f 47 61 70 cf 3f 67 1c b7 90 fb 90 6b c1 8b 38 49 10 6b 85 af 23 b1 ac 58 26 75 16 0e 3f 77 3e 9a f5 9c 8c 59 76 45 46 7d 06 e2 d1 d3 a6 47 0f 54 4f d8 f7 8c 5c 9e ed 4d 64 5c 60 b5 88 b3 9d 3a 97 e5 fa cc a5 f9 26 e4 50 b7 b0 e3 c4 5c ae 17 66 c7 10 2e 82 30 1d af a7 6b e9 84 4c 86 7d cd 9f 07 89 ac e5 a6 f0 03 18 17 7a ab 47 9a 86 8c b4 7d 7e b1 4a fc 12 44 74 94 5e 66 66 bb b0 09 10 a6 ce 51 0b 8b e3 f1 c4 5d f3 0f 5e 25 47 bf c9 1c 56 01 f1 7e ac a2 33 19 7b 7e d2 d1 ad 46 05 fd e0 be ce d8 0c 0f f7 a7 00 03 00 4b 17 4b 32 c5 ef da 24 1e 2d 42 d1 66 93 c9 90 ec 72 25 d4 71 20 2e db 83 50 e8 b1 30 df ae b2 56 44 97 8f 7e 98 e5 98 56 16 08 01 dc 4e"



# n_hex= "    00:e6:33:fb:66:ab:fd:bf:37:46:32:a8:16:f6:06:ed:97:df:ec:dd:01:4f:ba:96:75:2c:cf:ea:4d:37:af:67:33:6d:1a:34:f8:bd:40:7e:1e:93:2c:6c:ff:1f:ae:8f:7e:d9:97:0d:a1:0f:00:39:a6:27:c0:e3:89:05:b4:e5:e4:c3:57:b1:e2:54:b5:c7:1b:56:0a:e1:ae:d5:85:d3:0e:0c:52:d4:8d:5d:70:d6:b8:a9:d6:2f:c2:58:01:1b:2c:76:4f:41:9d:20:37:86:de:c5:8d:58:ec:76:39:70:5e:5b:ac:26:d1:14:71:a9:48:72:23:d4:97:68:df:32:41:6b:02:69:a8:cf:67:1c:3c:f4:e2:75:5d:a4:92:85:6a:df:0f:6c:6a:eb:19:90:61:5e:98:3f:a2:9c:20:e4:65:40:6d:b5:6b:a0:6f:0d:b7:b0:13:78:8c:d8:e1:80:9a:51:2f:fd:ae:ce:c9:d2:a5:7a:b5:ab:73:7a:05:04:1a:0e:9a:09:db:2e:e0:5a:c6:40:50:36:fd:14:42:b4:41:7c:1f:90:3a:80:f7:70:4d:ec:78:08:e4:7e:45:55:db:69:65:27:97:0c:9f:4d:18:c0:54:5d:b1:16:25:80:d1:64:a1:2d:e4:db:96:2c:4c:c6:fe:36:a9:46:62:74:75"

# hex_data ='00 02 09 ad 82 9f fb 3a 98 b9 1a 1b e5 3c 6d 61'\
# ' 88 45 6f 19 2e 85 0c 9d 23 89 98 a3 95 58 74 21 86 97 04'\
# ' 3f 5a 11 b4 93 6e fd 3f be c0 0b ed 3c 10 03 19 99 13 9c'\
# ' 04 4a 79 bb 94 75 cb 50 c7 2f d5 d8 6e 38 d3 c5 6c ab 5d'\
# ' 19 45 b9 31 d4 63 d9 58 6c 05 29 a2 c8 ca 8b b3 17 6a ba'\
# ' 6d 3e 32 de eb e0 bc a2 20 22 86 58 2a 08 93 33 f7 ca 7b'\
# ' 40 70 f2 72 00 68 65 6c 6c 6f 20 77 6f 72 6c 64 21'\


hex_data =' 00 02 09 ad 82 9f fb 3a 98 b9 1a 1b e5 3c 6d 61'\
' 88 45 6f 19 2e 85 0c 9d 23 89 98 a3 95 58 74 21 86 97 04'\
' 3f 5a 11 b4 93 6e fd 3f be c0 0b ed 3c 10 03 19 99 13 9c'\
' 04 4a 79 bb 94 75 cb 50 c7 2f d5 d8 6e 38 d3 c5 6c ab 5d'\
' 19 45 b9 31 d4 63 d9 58 6c 05 29 a2 c8 ca 8b b3 17 6a ba'\
' 6d 3e 32 de eb e0 bc a2 20 22 86 58 2a 08 93 33 f7 ca 7b'\
' 40 70 f2 72 00 68 65 6c 6c 6f 20 77 6f 72 6c 64 21'\



n_hex = "00:a5:8b:fc:62:ab:e4:0a:57:d2:87:86:0f:39:5a:77:05:ab:05:34:ee:b2:bb:59:11:31:a9:3d:62:7d:d2:56:4b:61:eb:de:2a:43:08:2a:50:fb:d8:4d:30:8d:1f:70:b7:cd:7d:c4:ac:a6:23:9a:be:46:ff:76:d2:a7:13:50:34:c2:f8:d4:77:d5:e1:43:8b:57:23:0b:15:7c:71:c1:eb:44:b6:2c:bf:5e:2c:ca:14:b9:56:97:9c:3b:48:e7:ae:44:75:dd:4d:b8:e7:2e:bd:55:59:bd:e3:f2:81:c8:ee:75:c0:8e:23:c6:96:0e:1e:16:69:fa:c9:1a:81:5c:67"

# cipher we are trying to decrypt
binary_data = bytes.fromhex(hex_data.replace(' ',''))
c = int(hex_data.replace(' ',''),16)

# checking padding oracle

print("m0 padding check :", padding_oracle(binary_data))



# modulus to integer
n = int(n_hex.replace(':',''), 16)
print("modulus int :",n)


# number of bytes in the modulus (n)
k= math.ceil(math.log(n, 256))
print("number of bytes in n :", math.ceil(k))


# B = "00 02 00*126 times"  -- 1024 bit ==> 128 bytes,  00 02 occupies 2 bytes

B = int(math.pow(2,(k-2)*8))
print("B in int :",B )
print("B in hex :",'{:0256x}'.format(B))
print("Length of B in hex :", len('{:02x}'.format(B)))


# computes the smallest integer greater than or equal to x/y
def ceil(x,y):
    # return x/y + (x%y != 0)
    return math.ceil(x/y)

m0 = c

s1 = ceil(n,3*B) # this is the starting value for s1
print("[-] Starting search for s1 (from value {})".format(s1))
i2a = 1          # counter for iterations
while True:
    m1 = (s1 * m0) % n

    hex_m1 = '{:0256x}'.format(m1)    
    # print("m1 :", hex_m1)
    if padding_oracle(bytes.fromhex(hex_m1)):   # call the (simulated) oracle
        break    # padding is correct, we have found s1
    i2a += 1
    s1 += 1      # try next value of s1
print("[*] Search done in {} iterations".format(i2a))
print("    s1: {}".format(s1))
