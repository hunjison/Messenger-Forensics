from Crypto.Cipher import AES
import binascii
import os

masterKey_hex = input("masterKey(hex) : ")
encryptedFile_PATH = input("encrypted File PATH : ")

masterKey = binascii.a2b_hex(masterKey_hex)

with open(encryptedFile_PATH, 'rb') as f:
    iv = f.read(16)
    encryptedFile = f.read()

cipher = AES.new(masterKey, AES.MODE_CBC, iv)
result = cipher.decrypt(encryptedFile)

with open(os.path.join(os.path.dirname(encryptedFile_PATH), 'recover_' + os.path.basename(encryptedFile_PATH)), 'wb') as f:
    f.write(result)

print("\nDecryption Success! ")
                       
