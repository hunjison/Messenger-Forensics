from Crypto.Cipher import AES
import binascii
import os

read_index = 0
write_buffer = b''

log_file_PATH = input("log File path : ")
log_key_input = input("log_key : ")

log_key = binascii.a2b_hex(log_key_input)

with open(log_file_PATH, 'rb') as f:
    log_file = f.read()

while len(log_file) != read_index:
    #######################################################
    ############## iv ( 16 bytes ) ########################
    ############## length ( 4 bytes ) #####################
    ############## encrypted data ( length bytes) #########
    #######################################################
    log_iv = log_file[read_index : read_index + 16]
    log_length = log_file[read_index + 16 : read_index + 20]
    log_length = int.from_bytes(log_length, "big")
    log_encrypted = log_file[read_index + 20 : read_index + 20 + log_length]
    read_index += (20 + log_length)

    aesCipher = AES.new(log_key, AES.MODE_CBC, iv=log_iv)
    result = aesCipher.decrypt(log_encrypted)
    write_buffer += result

with open(log_file_PATH + '_recover', 'wb') as f:
    f.write(write_buffer)

print("\nDecryption Success! ")

"""
length = 16 - (len(log_encrypted) % 16)
log_encrypted += bytes([length])*length
"""

