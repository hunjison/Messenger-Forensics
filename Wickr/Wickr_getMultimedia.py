from Crypto.Cipher import AES
import binascii
import hashlib
import os

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

if __name__ == "__main__":
    messagePayload_PATH = input("messagePayload(.bin) in your PC(full path): ")
    cachedText_PATH = input("cachedText(.txt) in your PC(full path): ")
    encrypted_file_PATH = input("encrypted file path in your PC(full path): ")

    with open(messagePayload_PATH, 'rb') as f:
        messagePayload = f.read()

    with open(cachedText_PATH, 'rb') as f:
        cachedText = f.read()

    with open(encrypted_file_PATH, 'rb') as f:
        encrypted_file = f.read()

    # not very correct, but \x32\x21\x00 is near the key.
    key_index = messagePayload.find(b'\x32\x21\x00') + 3
    key = messagePayload[key_index : key_index + 32]

    #AES-GCM-DECRYPT
    result = decrypt_AES_GCM(parse_data(encrypted_file), key)

    SAVE_DIR = os.path.dirname(os.path.abspath(messagePayload_PATH))
    with open(SAVE_DIR + '\\' + 'recover_' + cachedText.decode(), 'wb') as f:
        f.write(result)

    print(f"recover {os.path.basename(encrypted_file_PATH)} to {'recover_' + cachedText.decode()} success!")
