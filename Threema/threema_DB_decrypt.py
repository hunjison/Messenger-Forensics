import binascii
import hashlib

OBFUSCATION_KEY = b"\x95\x0d\x26\x7a\x88\xea\x77\x10\x9c\x50\xe7\x3f\x47\xe0\x69\x72\xda\xc4\x39\x7c\x99\xea\x7e\x67\xaf\xfd\xdd\x32\xda\x35\xf7\x0c"

def derivePassphraseKey(passphrase):
    # pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None)
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), salt, 10000, 32)

def verify(verification, masterKey):
    sha1 = hashlib.sha1()
    sha1.update(masterKey)

    if verification != sha1.digest()[:4]:
        raise Exception
    else:
        print("Verification Success!")

def masterKey_to_databaseKey(masterKey):
    print(f'databaseKey : x"{masterKey.hex()}"')
    print('''
"PRAGMA cipher_default_page_size = 4096;" +
"PRAGMA cipher_default_kdf_iter = 1;" +
"PRAGMA cipher_default_hmac_algorithm = HMAC_SHA512;" +
"PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;");')''')
    
key_PATH = input("key.dat PATH: ")


with open(key_PATH, 'rb') as f:
    protectedFlag = f.read(1)
    protectedKey = f.read(32)

    salt = f.read(8)
    verification = f.read(4)

masterKey = b""
_protectedKey = b""
print("protectedFlag : ", protectedFlag)

# DE-OBFUSCATION
for i,j in zip(protectedKey, OBFUSCATION_KEY):
    _protectedKey += bytes([i^j])

if protectedFlag != b'\x00': # if locked = true

    # checkPassphrase() and unlock()
    passphrase = input("User password : ")
    passphraseKey = derivePassphraseKey(passphrase)

    for i,j in zip(_protectedKey, passphraseKey):
        masterKey += bytes([i^j])
    

else : # if locked = false
    masterKey = _protectedKey

verify(verification, masterKey)

print("salt : ", binascii.hexlify(salt))
print("masterKey : ", binascii.hexlify(masterKey))
masterKey_to_databaseKey(masterKey)

    
