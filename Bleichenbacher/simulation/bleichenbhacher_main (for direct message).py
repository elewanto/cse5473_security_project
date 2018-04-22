import math
from binascii import *
from Crypto.PublicKey import RSA

def int_hex(n):
    string = '{:0256x}'.format(n)
    return ' '.join([string[i:i+2] for i in range(0, len(string), 2)])


def padding_oracle(number):
    hex_number = '{:0256x}'.format(number)

    if hex_number[:4] == "0002":
        if '00' in hex_number[4:]:
            return True
    return False

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
    r_count = 0
    for (a,b) in interval_set: # for all intervals which will be shrinked
        for r in range(ceil((a*x - B3 + 1),n),
                       floor((b*x - B2),n) + 1):
            possible_shrink_left = ceil((B2 + r*n),x)
            possible_shrink_right = floor((B3 - 1 + r*n),x)
            new_interval_left = max(a,possible_shrink_left)
            new_interval_right = min(b,possible_shrink_right)

            if new_interval_left <= new_interval_right:
                newM |= set([ (new_interval_left, new_interval_right) ])
            # print("Value of r:   {}".format(r))
            # print(newa)
            # print(newb)
            r_count +=1
    print("Total intervals checked: "+ str(r_count))        
    print("Next Interval candidates ("+str(len(newM))+"): ", newM)
    return newM



def search_multiplier(msg, n, x):
    print ("[-] Starting search for x (from value %i)" % x)
    num_of_interations = 1          # counter for iterations
    while True:
        next_landing_msg = (x * msg) % n
        if padding_oracle(next_landing_msg):   # call the (simulated) oracle
            break    # padding is correct, we have found x
        num_of_interations += 1
        x += 1      # try next value of x
    print ("Found next correct padding in %i iterations" % num_of_interations)
    print ("    x: %i" % x)
    return x

def search_multiplier_binary(m, n, x, a, b):
    B2 = padding_start
    B3 = padding_end + 1
    r = ceil((b*x - B2)*2,n) # starting value for r
    i2c,nr = 0,1    # for statistics
    found = False
    while not found:
        for x in range(ceil((B2 + r * n),b), floor((B3-1 + r * n),a)+1):
            mi = (x * m) % n
            i2c += 1
            if padding_oracle(mi):
                found = True
                break # we found x
        if not found:
            r  += 1   # try next value for r
            nr += 1
    print( "Found next correct padding in %i iterations" % (i2c))
    print( "   Number of r explored:  %i" % nr)
    print( "    multiplier_%i:                    %i" % (i2c, x))
    return x

# ------------------------


f = open("public.pem", "r")
key = RSA.importKey(f.read())


hex_data =' 00 02 09 ad 82 9f fb 3a 98 b9 1a 1b e5 3c 6d 61'\
' 88 45 6f 19 2e 85 0c 9d 23 89 98 a3 95 58 74 21 86 97 04'\
' 3f 5a 11 b4 93 6e fd 3f be c0 0b ed 3c 10 03 19 99 13 9c'\
' 04 4a 79 bb 94 75 cb 50 c7 2f d5 d8 6e 38 d3 c5 6c ab 5d'\
' 19 45 b9 31 d4 63 d9 58 6c 05 29 a2 c8 ca 8b b3 17 6a ba'\
' 6d 3e 32 de eb e0 bc a2 20 22 86 58 2a 08 93 33 f7 ca 7b'\
' 40 70 f2 72 00 68 65 6c 6c 6f 20 77 6f 72 6c 64 21'\


m = int(hex_data.replace(' ',''),16)
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
    print('-----------------------------------------------------\n')    


# for m in range(interval_start, interval_end+1):
#     belichenbacher(m, n, multiplier, padding_start, padding_end, interval_start, interval_end, loop_time)
