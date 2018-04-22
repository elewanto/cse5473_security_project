import math

def belichenbacher(m, n, multiplier, padding_start, padding_end, interval_start, interval_end, loop_time):
    
    r = 0 # multiples of n before a padding match occures
    ms_mod_n_previous = m
    print('m :',m)
    s_match = 0 # values of s when first padding match occures
    s_match_not_found_yet = True 
    for s in range(multiplier,loop_time):
        ms = m*s
        ms_mod_n = ms%n

        if (ms_mod_n_previous > ms_mod_n) and s_match_not_found_yet:
            r +=1

        ms_mod_n_previous = ms_mod_n

        if ms_mod_n >= padding_start and  ms_mod_n <= padding_end:
            print("{:>5} {:>5} {:>5} {:>5} <--".format(s, r, ms, ms_mod_n))

            if s_match_not_found_yet:
                s_match = s
                s_match_not_found_yet = False
                break
        else:
            print("{:>5} {:>5} {:>5} {:>5}".format(s, r, ms, ms_mod_n))    

    print('>>----------------------------------------------------')
    print('New m Interval: ['+ str(math.ceil((padding_start+r*n)/s_match)) + ', ' + str(math.floor((padding_end+r*n)/s_match)) + ']')

    print('New r Interval: ['+ str(math.ceil((interval_start*s_match-padding_end)/n )) + ', ' + str(math.floor( ( interval_end*s_match-padding_start)/n)) + ']')
    print('----------------------------------------------------<<')




# padding_start, padding_end = 30, 40
# interval_start, interval_end =  30, 40
# n = 100 # the modulus
# m = 35 # the message
# loop_time = 50
# multiplier = 2
# belichenbacher(m, n, multiplier, padding_start, padding_end, interval_start, interval_end, loop_time)


padding_start, padding_end = 10, 14
interval_start, interval_end =  10, 14
n = 41 # the modulus

loop_time = 1000
multiplier = 2

for m in range(interval_start, interval_end+1):
    belichenbacher(m, n, multiplier, padding_start, padding_end, interval_start, interval_end, loop_time)

