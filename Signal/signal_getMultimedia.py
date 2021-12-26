from Crypto.Cipher import AES
from Crypto.Util import Counter
from binascii import hexlify
import base64
import hmac
import hashlib
import os

file_name = input("file_name(for save) : ")
modernKey_raw = input("modernKey : ")
data_random_PATH = input("data_random File path : ")
encryptedFile_PATH = input("encrypted File path : ")


with open(data_random_PATH, 'rb') as f:
    data_random = f.read()    

with open(encryptedFile_PATH, 'rb') as f:
    cipherText = f.read()         

modernKey_raw2 = modernKey_raw + '=' * (4-len(modernKey_raw)%4)
modernKey = base64.b64decode(modernKey_raw2)

key = hmac.new(modernKey, data_random, hashlib.sha256).digest()

specific_IV = 0 
counter_value = Counter.new(128, initial_value=specific_IV)
aesCipher = AES.new(key, AES.MODE_CTR, counter = counter_value)
result = aesCipher.decrypt(cipherText)

with open(os.path.join(os.path.dirname(encryptedFile_PATH),file_name), 'wb') as f:
    f.write(result)

print("\nDecryption Success! ")

