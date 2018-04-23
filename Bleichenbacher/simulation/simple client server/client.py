# Import socket module
import socket               
 
# Create a socket object
sock = socket.socket()         
 
# Define the port on which you want to connect
port = 4443               
 
# connect to the server on local computer
sock.connect(('10.1.2.5', port))

cipher = "afe2ca9f5f39faa55766a09a5580ff571103616f4e671002af60359dfa2b40ee5edd33de0d0cb532d28a29a32c4006320b1f78eec533d83f9f6399f6764d4d260df0e32248d1599101fe07095e3f56bb57290431af7143bbc7f83b3d75e09ecb0270256986da37d7b6ad24d350a4b1f99a8a9ed39ee1c71d7afbd8a7faf37e22"

sock.send(cipher.encode())

oracle_answer = sock.recv(1024).decode()

# receive data from the server
print(oracle_answer)


# close the connection
sock.close()       
