from Crypto.PublicKey import RSA


f = open("public.pem", "r")
key = RSA.importKey(f.read())


def int_hex(n):
    string = '{:0256x}'.format(key.n)
    return ' '.join([string[i:i+2] for i in range(0, len(string), 2)])



#displays n
print("n: ",key.n) 
# print('n_hex: ', ''.join("{:02x}".format((ord(c)) for c in  '{:0256x}'.format(key.n) ) ))
print('n_hex: ', int_hex(key.n)  ) 

"""00:c1:ec:1c:1e:e9:5d:cb:24:4a:70:f2:8c:e0:ca:
58:70:04:64:cc:10:89:0e:99:eb:c6:cd:9e:24:38:
9c:3e:df:da:3c:2d:fe:3e:45:60:c5:04:c9:c7:da:
75:57:ab:2e:50:c9:f4:1e:53:50:96:a7:3d:7c:57:
64:68:68:04:df:cb:0c:17:4d:a1:f1:32:cd:38:5b:
92:b4:03:58:18:68:bb:d8:12:22:ca:85:78:9f:96:
a2:5e:06:c0:66:f0:a9:75:c9:59:73:1e:68:48:37:
58:fa:5b:32:d2:e2:d1:b2:67:ce:21:e6:db:04:9f:
01:7c:2d:05:b2:dd:42:c3:c3
"""

print(key.e) #displays e

