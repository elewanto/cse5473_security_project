interval_start =  10

interval_end = 15

n = 41 # the modulus

m = 13 # the message

line_offset = 2
line_start = 0 + line_offset 
line_end = 180 + line_offset

line_interval_start = 10 + line_offset 
line_interval_end = 20  + line_offset

fill_char = '-'

print(' '*line_offset+
      '|'+ fill_char*(line_interval_start -line_start)+
      '|'+ fill_char*(line_interval_end - line_interval_start)+
      '|'+ fill_char*(line_end - line_interval_end)+
      '|'
      ) 

for s in range(1,50):
    ms = m*s
    ms_mod_n = ms%n

    fill_char = '^'

    print(' '*line_offset+
      '|'+ fill_char*(line_interval_start -line_start)+
      '|'+ fill_char*(line_interval_end - line_interval_start)+
      '|'+ fill_char*(line_end - line_interval_end)+
      '|'
      ) 

    if ms_mod_n >= interval_start and  ms_mod_n < interval_end:
        print("{:>5} {:>5} {:>5}".format(s, ms, ms_mod_n))
