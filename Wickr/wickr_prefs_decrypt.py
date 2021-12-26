import os
from Crypto.Cipher import AES
import binascii
import hashlib
import xml.etree.cElementTree as ET
import re
import base64
import json

def encrypt_AES_GCM(msg, secretKey):
  aesCipher = AES.new(secretKey, AES.MODE_GCM)
  ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
  return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, secretKey):
  (ciphertext, nonce, authTag) = encryptedMsg
  aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
  plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
  return plaintext

def parse_data(data):
    data = data[1:]
    ciphertext = data[28:]
    authTag = data[12:28] # len = 16
    nonce = data[:12] # len = 12
    return (ciphertext, nonce, authTag)

def cachedkey_to_dbkey(data):
    return data[0x4:0x25]

def androidID_to_deviceKey(s):
    #md5 hash
    md5 = hashlib.md5(s.encode()).hexdigest()

    #convert to uuid format
    uuid = list(md5)
    for i in [8, 13, 18, 23]:
      uuid.insert(i, '-')

    #substitution
    uuid[14] = '3'
    case = int(uuid[19],16) % 4
    uuid[19] = hex(8 + case)[2:]
    uuid = ''.join(uuid)
    print("UUID generated: ", uuid)

    #sha256
    sha256 = hashlib.sha256(uuid.encode()).hexdigest()
    return binascii.unhexlify(sha256)

if __name__ == "__main__":
    Wickr_PATH = input("Wickr PATH(copy of '/data/data/<PACKAGE>' in your PC): ")
    android_id_PATH = input("Android_id(copy of '/data/system/users/<User_ID>/settings_ssaid.xml' in your PC): ")
    log_file_PATH = input("pref file PATH :")

    # READ log file
    with open(log_file_PATH, 'rb') as f:
      log_file = f.read()                     

    # READ android_id(settings_ssaid.xml)
    with open(r"C:\Users\esby9\Desktop\Signal\[PAPER]EXPERIMENT\FileTEST(A20e)\com.mywickr.wickr2\settings_ssaid.xml") as f:
      xml = f.read()
    tree = ET.fromstring(re.sub(r"(<\?xml[^>]+\?>)", r"\1<root>", xml) + "</root>")
    wickr_setting = tree.find('./settings/setting[@package="com.mywickr.wickr2"]') # if error occurs, try "com.mywickr.wickr2-1"

    android_id = wickr_setting.attrib['value']

    # Pref Decryption Start!
    deviceKey = androidID_to_deviceKey(android_id)

    print("Pref Decryption Start!")
    result = decrypt_AES_GCM(parse_data(log_file), deviceKey)

    with open(os.path.join(log_file_PATH + '_recover'), 'wb') as f:
        f.write(result)

    print("result : ", result)
    print("\nDecryption Success! ")






  
  
