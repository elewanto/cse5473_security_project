# first of all import the socket library
import socket               
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import binascii



server_private_key_file = "/media/sf_Bleichenbacher/tlslite-ng-master/scripts/mj_keys/private.pem"
rsa_key = RSA.importKey(open(server_private_key_file, "rb").read())


def padding_oracle(cipher):

    cipher_bytes = bytes.fromhex(cipher)
    decrypted = rsa_key.decrypt(cipher_bytes)

    # print( len(decrypted))
    # print(rsa_key.n)
    # print(decrypted)

    # print("\n")

    print('{:0256x}'.format(int(binascii.hexlify(decrypted), 16)))

    cipher_hex = '{:0256x}'.format(int(binascii.hexlify(decrypted), 16))

    if cipher_hex[:4] == "0002":
        if '00' in cipher_hex[4:]:
            return True
    return False

# next create a socket object
sock = socket.socket()         
print("Socket successfully created")
 
# reserve a port on your computer in our
# case it is 12345 but it can be anything
port = 4443
 
# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests 
# coming from other computers on the network
sock.bind(('10.1.2.5', port))
print("socket binded to %s" %(port))
 
# put the socket into listening mode
sock.listen(5)     
print("socket is listening"           )
 
# a forever loop until we interrupt it or 
# an error occurs

connection = None
while True:
    try:
        # Establish connection with client.
        connection, address = sock.accept()
        print("connected from ", address)

        # receive cipher
        recv_cipher = connection.recv(1024).decode()

        print(recv_cipher)

        # send a thank you message to the client.
        connection.send((str(padding_oracle(recv_cipher))).encode())

        
    except KeyboardInterrupt:
        # Close the connection with the client
        if connection:  
           connection.close()
        break

    except Exception as e:
        print(traceback.format_exception(*sys.exc_info()))
        # Close the connection with the client
        if connection:  
           connection.close()
        break
