import math
def SO(number):
    if number >= padding_start and number <= padding_end:
        return True
    else:
        return False


# -------------------------------- Official code from web http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html 
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


def find_new_short_intervals(x, interval_set):
    # Narrowing the interval
    B2 = padding_start
    B3 = padding_end + 1
    newM = set([])
    for (a,b) in interval_set: # for all intervals
        for r in range(math.ceil((a*x - B3 + 1)/n),
                       math.floor((b*x - B2)/n) + 1):
            aa = math.ceil((B2 + r*n)/x)
            bb = math.floor((B3 - 1 + r*n)/x)
            newa = max(a,aa)
            newb = min(b,bb)

            if newa <= newb:
                newM |= set([ (newa, newb) ])
            print("Value of r:   {}".format(r))
            print(newa)
            print(newb)
    print("Next candidates :", newM)
    return newM


# computes the smallest integer greater than or equal to x/y
def ceil(x,y):
    # return x/y + (x%y != 0)
    return math.ceil(x/y)

def search_multiplier(m, n, x):
    print ("[-] Starting search for x (from value %i)" % x)
    i2a = 1          # counter for iterations
    while True:
        m1 = (x * m) % n
        if SO(m1):   # call the (simulated) oracle
            break    # padding is correct, we have found x
        i2a += 1
        x += 1      # try next value of x
    print ("[*] Search done in %i iterations" % i2a)
    print ("    x: %i" % x)
    return x

def search_multiplier_binary(m, n, x, a, b):
    B2 = padding_start
    B3 = padding_end + 1
    r = ceil((b*x - B2)*2,n) # starting value for r
    i2c,nr = 0,1    # for statistics
    found = False
    while not found:
        for x in range(math.ceil((B2 + r * n)/b), math.floor((B3-1 + r * n)/a)+1):
            mi = (x * m) % n
            i2c += 1
            if SO(mi):
                found = True
                break # we found x
        if not found:
            r  += 1   # try next value for r
            nr += 1
    print( "[*] Search done in %i iterations" % (i2c))
    print( "    explored values of r:  %i" % nr)
    # print( "    s_%i:                    %i" % (iter,x))
    print( "    s_%i:                    %i" % (i2c, x))
    return x


# --------------------------------------------------------<

# padding_start, padding_end = 10, 14
# n = 41 # the modulus
# m = 14


# padding_start, padding_end = 80, 100
# n = 1000 # the modulus
# m = 91

padding_start, padding_end = 200, 300
n = 1001 # the modulus
m = 210

x = math.ceil(n/(padding_end+1)) # multiplier 
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
        break
    else:
        do_binary_search = False 
        x= x+1
    print('-----------------------------------------------------\n')    


# for m in range(interval_start, interval_end+1):
#     belichenbacher(m, n, multiplier, padding_start, padding_end, interval_start, interval_end, loop_time)
