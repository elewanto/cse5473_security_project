import math

def belichenbacher(m, n, interval_start, interval_end, loop_time):
    
    r = 0 # multiples of n before a padding match occures
    ms_mod_n_previous = m

    s_match = 0 # values of s when first padding match occures
    s_match_not_found_yet = True 
    for s in range(2,loop_time):
        ms = m*s
        ms_mod_n = ms%n

        if (ms_mod_n_previous > ms_mod_n) and s_match_not_found_yet:
            r +=1

        ms_mod_n_previous = ms_mod_n

        if ms_mod_n >= interval_start and  ms_mod_n < interval_end:
            print("{:>5} {:>5} {:>5} <--".format(s, ms, ms_mod_n))

            if s_match_not_found_yet:
                s_match = s
                s_match_not_found_yet = False
                break
        else:
            print("{:>5} {:>5} {:>5}".format(s, ms, ms_mod_n))    

    print('>>----------------------------------------------------')
    print('New m Interval: ['+ str(math.ceil((interval_start+r*n)/s_match)) + ', ' + str(math.floor(((interval_end-1)+r*n)/s_match)) + ']')

    print('New r Interval: ['+ str(math.ceil((interval_start+r*n)/s_match)) + ', ' + str(math.floor(((interval_end-1)+r*n)/s_match)) + ']')

    print('------------------------------------------------------<<')

# interval_start =  10
# interval_end = 15
# n = 41 # the modulus
# m = 13 # the message
# loop_time = 50
# belichenbacher(m, n, interval_start, interval_end, loop_time)

# interval_start =  10
# interval_end = 20
# n = 100 # the modulus
# m = 18 # the message
# loop_time = 50
# belichenbacher(m, n, interval_start, interval_end, loop_time)

# interval_start =  10
# interval_end = 20
# n = 100 # the modulus
# m = 18 # the message
# loop_time = 50
# belichenbacher(m, n, interval_start, interval_end, loop_time)


interval_start =  10
interval_end = 40
n = 100 # the modulus
m = 35 # the message
loop_time = 50
belichenbacher(m, n, interval_start, interval_end, loop_time)


# #------------- two interval

# interval_start =  120
# interval_end = 150
# n = 1000 # the modulus
# m = 141 # the message
# loop_time = 1000
# belichenbacher(m, n, interval_start, interval_end, loop_time)


# interval_start =  140
# interval_end = 143
# n = 1000 # the modulus
# m = 141 # the message
# loop_time = 1000
# belichenbacher(m, n, interval_start, interval_end, loop_time)

# #------------- two interval end


