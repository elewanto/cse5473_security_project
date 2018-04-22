import math
from binascii import *
from Crypto.PublicKey import RSA
import binascii



server_private_key_file = "/home/mohit/Dropbox/network_security_OSU/main_project/cse5473_security_project/Bleichenbacher/tlslite-ng-master/scripts/mj_keys/private.pem"
rsa_key = RSA.importKey(open(server_private_key_file, "rb").read())


def padding_oracle(cipher):

    # cipher_bytes = bytes.fromhex(cipher)
    decrypted = rsa_key.decrypt(cipher)

    # print( len(decrypted))
    # print(rsa_key.n)
    # print(decrypted)

    # print("\n")

    # print('{:0256x}'.format(int(binascii.hexlify(decrypted), 16)))

    cipher_hex = '{:0256x}'.format(int(binascii.hexlify(decrypted), 16))

    if cipher_hex[:4] == "0002":
        if '00' in cipher_hex[4:]:
            return True
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


cipher_hex = 'af:e2:ca:9f:5f:39:fa:a5:57:66:a0:9a:55:80:ff:57:11:03:61:6f:4e:67:10:02:af:60:35:9d:fa:2b:40:ee:5e:dd:33:de:0d:0c:b5:32:d2:8a:29:a3:2c:40:06:32:0b:1f:78:ee:c5:33:d8:3f:9f:63:99:f6:76:4d:4d:26:0d:f0:e3:22:48:d1:59:91:01:fe:07:09:5e:3f:56:bb:57:29:04:31:af:71:43:bb:c7:f8:3b:3d:75:e0:9e:cb:02:70:25:69:86:da:37:d7:b6:ad:24:d3:50:a4:b1:f9:9a:8a:9e:d3:9e:e1:c7:1d:7a:fb:d8:a7:fa:f3:7e:22'


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
    


# for m in range(interval_start, interval_end+1):
#     belichenbacher(m, n, multiplier, padding_start, padding_end, interval_start, interval_end, loop_time)
