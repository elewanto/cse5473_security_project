from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

hex_data = "779f65c6cae8b649df83a06b6db9dfa0456f416191b4b34adf30607acd0cbd1be7e7ed9df40d2a8904c69822102d56cc13748931160dc9fd003e266205b6716801c082ed1f997759aab570449510f05206b44f3121ab0f822c1adf540ca5f43859eeb6de188ce72bb8c55b629cb0593341b27c544faeae06967ca00a19bb5fe438b411fe3d555e63a48fa96bb205b462d2f03e5663efd2f8bc252f0d8ca85997776c92a4e2815c47988b6d3090a0d6d6597b11c7139eea707f71b95f382f8fa44e0072ebe1da049eb3c7fb1c9c055ec5fa5cf833f654ea81e6ffd00cdb835abf5a358b30a17b7ed74e558a81d3351ae407c141775fa23ec26d59b3b71128404e"

data_to_verify = bytes.fromhex(hex_data)


verification_key_file = "/home/mohit/VirtualBox VMs/vm_shared_folder/tlslite-ng-master/tests/serverX509Key.pem"

rsa_key = RSA.importKey(open(verification_key_file, "rb").read())

decrypted = rsa_key.decrypt(data_to_verify)

print( len(decrypted))
print(rsa_key.n)
print(decrypted)

# b'\x02\x9d\xb3Xp\x16\xbc\x0cIY~\r\xa7\xbd\x12]\x89\xd3\xd8{\x9a.k8\x9e\x03\xa2\x06\xbd\xdc`\xf4\x8c\xb5\xa3\x9fGap\xcf?g\x1c\xb7\x90\xfb\x90k\xc1\x8b8I\x10k\x85\xaf#\xb1\xacX&u\x16\x0e?w>\x9a\xf5\x9c\x8cYvEF}\x06\xe2\xd1\xd3\xa6G\x0fTO\xd8\xf7\x8c\\\x9e\xedMd\\`\xb5\x88\xb3\x9d:\x97\xe5\xfa\xcc\xa5\xf9&\xe4P\xb7\xb0\xe3\xc4\\\xae\x17f\xc7\x10.\x820\x1d\xaf\xa7k\xe9\x84L\x86}\xcd\x9f\x07\x89\xac\xe5\xa6\xf0\x03\x18\x17z\xabG\x9a\x86\x8c\xb4}~\xb1J\xfc\x12Dt\x94^ff\xbb\xb0\t\x10\xa6\xceQ\x0b\x8b\xe3\xf1\xc4]\xf3\x0f^%G\xbf\xc9\x1cV\x01\xf1~\xac\xa23\x19{~\xd2\xd1\xadF\x05\xfd\xe0\xbe\xce\xd8\x0c\x0f\xf7\xa7\x00\x03\x00K\x17K2\xc5\xef\xda$\x1e-B\xd1f\x93\xc9\x90\xecr%\xd4q .\xdb\x83P\xe8\xb10\xdf\xae\xb2VD\x97\x8f~\x98\xe5\x98V\x16\x08\x01\xdcN'






print("\n")
print(' '.join('{:02x}'.format(x) for x in decrypted) )
# 02 9d b3 58 70 16 bc 0c 49 59 7e 0d a7 bd 12 5d 89 d3 d8 7b 9a 2e 6b 38 9e 03 a2 06 bd dc 60 f4 8c b5 a3 9f 47 61 70 cf 3f 67 1c b7 90 fb 90 6b c1 8b 38 49 10 6b 85 af 23 b1 ac 58 26 75 16 0e 3f 77 3e 9a f5 9c 8c 59 76 45 46 7d 06 e2 d1 d3 a6 47 0f 54 4f d8 f7 8c 5c 9e ed 4d 64 5c 60 b5 88 b3 9d 3a 97 e5 fa cc a5 f9 26 e4 50 b7 b0 e3 c4 5c ae 17 66 c7 10 2e 82 30 1d af a7 6b e9 84 4c 86 7d cd 9f 07 89 ac e5 a6 f0 03 18 17 7a ab 47 9a 86 8c b4 7d 7e b1 4a fc 12 44 74 94 5e 66 66 bb b0 09 10 a6 ce 51 0b 8b e3 f1 c4 5d f3 0f 5e 25 47 bf c9 1c 56 01 f1 7e ac a2 33 19 7b 7e d2 d1 ad 46 05 fd e0 be ce d8 0c 0f f7 a7 00 03 00 4b 17 4b 32 c5 ef da 24 1e 2d 42 d1 66 93 c9 90 ec 72 25 d4 71 20 2e db 83 50 e8 b1 30 df ae b2 56 44 97 8f 7e 98 e5 98 56 16 08 01 dc 4e

# Premaster secret
# 4b 17 4b 32 c5 ef da 24 1e 2d 42 d1 66 93 c9 90 ec 72 25 d4 71 20 2e db 83 50 e8 b1 30 df ae b2 56 44 97 8f 7e 98 e5 98 56 16 08 01 dc 4e

# 029db3587016bc0c49597e0da7bd125d89d3d87b9a2e6b389e03a206bddc60f48cb5a39f476170cf3f671cb790fb906bc18b3849106b85af23b1ac582675160e3f773e9af59c8c597645467d06e2d1d3a6470f544fd8f78c5c9eed4d645c60b588b39d3a97e5facca5f926e450b7b0e3c45cae1766c7102e82301dafa76be9844c867dcd9f0789ace5a6f00318177aab479a868cb47d7eb14afc124474945e6666bbb00910a6ce510b8be3f1c45df30f5e2547bfc91c5601f17eaca233197b7ed2d1ad4605fde0beced80c0ff7a70003004b174b32c5efda241e2d42d16693c990ec7225d471202edb8350e8b130dfaeb25644978f7e98e59856160801dc4e


# verifier = PKCS1_v1_5.new(rsa_key)
# h = SHA.new( data_to_verify)
# if verifier.verify(h, signature_received_with_the_data):
#     print("OK")
# else:
#     print("Invalid")