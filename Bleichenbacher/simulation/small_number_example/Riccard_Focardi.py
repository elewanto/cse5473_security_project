import math
def SO(number):
    if number >= padding_start and number <= padding_end:
        return True
    else:
        return False

# -------------------------------- Official code from web
def narrowing_the_interval (s1, B2, B3):
    # Narrowing the interval
    # B2,B3 = 2*B,3*B # constants to avoid recomputing them any time
    newM = set([])  # collects new intervals
    # the + 1  in the range function is to include last value (note that range does not include end value in it's function)
    for r in range(math.ceil((B2*s1 - B3 + 1)/n), math.floor(((B3-1)*s1 - B2)/n) + 1):
        aa = math.ceil((B2 + r*n)/s1)
        bb = math.floor((B3 - 1 + r*n)/s1)
        newa = max(B2,aa)
        newb = min(B3-1,bb)
        if newa <= newb:
            newM |= set([ (newa, newb) ])
        print("Value of r:   {}".format(r))
        print(newa)
        print(newb)
        print("Next candidates :", newM)


# computes the smallest integer greater than or equal to x/y
def ceil(x,y):
    # return x/y + (x%y != 0)
    return math.ceil(x/y)

def search_s1(m0, n, B2, B3):
    s1 = ceil(n,B3) # this is the starting value for s1
    print ("[-] Starting search for s1 (from value %i)" % s1)
    i2a = 1          # counter for iterations
    while True:
        m1 = (s1 * m0) % n
        if SO(m1):   # call the (simulated) oracle
            break    # padding is correct, we have found s1
        i2a += 1
        s1 += 1      # try next value of s1
    print ("[*] Search done in %i iterations" % i2a)
    print ("    s1: %i" % s1)
    narrowing_the_interval(s1, B2, B3)



# --------------------------------------------------------<






padding_start, padding_end = 10, 14
interval_start, interval_end =  10, 14
n = 41 # the modulus
m = 14
loop_time = 1000
multiplier = 2

search_s1(m, n, padding_start, padding_end +1 )
# for m in range(interval_start, interval_end+1):
#     belichenbacher(m, n, multiplier, padding_start, padding_end, interval_start, interval_end, loop_time)
