from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import binascii



hex_data = "779f65c6cae8b649df83a06b6db9dfa0456f416191b4b34adf30607acd0cbd1be7e7ed9df40d2a8904c69822102d56cc13748931160dc9fd003e266205b6716801c082ed1f997759aab570449510f05206b44f3121ab0f822c1adf540ca5f43859eeb6de188ce72bb8c55b629cb0593341b27c544faeae06967ca00a19bb5fe438b411fe3d555e63a48fa96bb205b462d2f03e5663efd2f8bc252f0d8ca85997776c92a4e2815c47988b6d3090a0d6d6597b11c7139eea707f71b95f382f8fa44e0072ebe1da049eb3c7fb1c9c055ec5fa5cf833f654ea81e6ffd00cdb835abf5a358b30a17b7ed74e558a81d3351ae407c141775fa23ec26d59b3b71128404e"

data_to_verify = binascii.unhexlify(hex_data)


verification_key_file = "/home/mohit/VirtualBox VMs/vm_shared_folder/tlslite-ng-master/tests/serverX509Key.pem"

rsa_key = RSA.importKey(open(verification_key_file, "rb").read())

decrypted = rsa_key.decrypt(data_to_verify)

print( len(decrypted))


# print(binascii.hexlify(decrypted)) 
print(''.join( [ "%02x " % ord( x ) for x in decrypted ] ).strip()) 
# 02 9d b3 58 70 16 bc 0c 49 59 7e 0d a7 bd 12 5d 89 d3 d8 7b 9a 2e 6b 38 9e 03 a2 06 bd dc 60 f4 8c b5 a3 9f 47 61 70 cf 3f 67 1c b7 90 fb 90 6b c1 8b 38 49 10 6b 85 af 23 b1 ac 58 26 75 16 0e 3f 77 3e 9a f5 9c 8c 59 76 45 46 7d 06 e2 d1 d3 a6 47 0f 54 4f d8 f7 8c 5c 9e ed 4d 64 5c 60 b5 88 b3 9d 3a 97 e5 fa cc a5 f9 26 e4 50 b7 b0 e3 c4 5c ae 17 66 c7 10 2e 82 30 1d af a7 6b e9 84 4c 86 7d cd 9f 07 89 ac e5 a6 f0 03 18 17 7a ab 47 9a 86 8c b4 7d 7e b1 4a fc 12 44 74 94 5e 66 66 bb b0 09 10 a6 ce 51 0b 8b e3 f1 c4 5d f3 0f 5e 25 47 bf c9 1c 56 01 f1 7e ac a2 33 19 7b 7e d2 d1 ad 46 05 fd e0 be ce d8 0c 0f f7 a7 00 03 00 4b 17 4b 32 c5 ef da 24 1e 2d 42 d1 66 93 c9 90 ec 72 25 d4 71 20 2e db 83 50 e8 b1 30 df ae b2 56 44 97 8f 7e 98 e5 98 56 16 08 01 dc 4e