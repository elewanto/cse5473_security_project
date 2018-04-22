from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import binascii



server_private_key_file = "/home/mohit/Dropbox/network_security_OSU/main_project/cse5473_security_project/Bleichenbacher/tlslite-ng-master/scripts/mj_keys/private.pem"
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

cipher = "afe2ca9f5f39faa55766a09a5580ff571103616f4e671002af60359dfa2b40ee5edd33de0d0cb532d28a29a32c4006320b1f78eec533d83f9f6399f6764d4d260df0e32248d1599101fe07095e3f56bb57290431af7143bbc7f83b3d75e09ecb0270256986da37d7b6ad24d350a4b1f99a8a9ed39ee1c71d7afbd8a7faf37e22"

print(padding_oracle(cipher))