# Messenger-Forensics
Forensic Analysis of Instant Messengers: Decrypt Signal, Wickr, and Threema

--- 

## Our Contributions
- We presented a methodology for analyzing the decryption algorithm of instant messenger. We extracted data from both unrooted and rooted devices and performed static and dynamic analysis on messenger applications.
- We decrypted all encrypted files of Signal, Wickr, and Threema. Compared to previous studies, our study found a new decryption algorithm, expanded the range of decryptable files, and corrected outdated parameters.
- We described the decryption algorithms in detail and have released all decryption scripts through ***GitHub***(this repository).

## How to extract data from unrooted devices
- We found a way to acquire INTERNAL data through the **“Messenger Backup Migration”**.
- We described the data extraction process in detail in our paper.

---

## Messenger Decryption
We use `python3` to all scripts and write description based on our paper.

### Signal Decryption
- Signal's decryption process is described in Table 2.
- We developed an [app](Signal/XXX) that can steal the key of Signal’s Android Keystore. This app can do `Step1` process. With the decrypted `pref_database_encrypted_secret` output from the app, we can decrypt the database.
- [signal_getMultimedia.py](Signal/signal_getMultimedia.py) can do `Step2` and `Step3` process and extract the multimedia decryption key. This file requires output from the app.
- [signal_log_decrypt.py](Signal/signal_log_decrypt.py) can do `Step4` process and extract the log decryption key. This file requires output from the app.

### Wickr Decryption
- Wickr's decryption process is described in Table 4.
- [Wickr_getDBKey.py](Wickr/Wickr_getDBKey.py) can do `Step1~3` process and extract the database decryption key.
- [Wickr_getMultimedia.py](Wickr/Wickr_getMultimedia.py) can do `Step4` process and extract the multimedia decryption key.
- [wickr_prefs_decrypt.py](Wickr/wickr_prefs_decrypt.py) can do `Step1` and `Step5` process and extract the preference decryption key.

### Threema Decryption
- Threema's decryption process is described in Table 8.
- [threema_DB_decrypt.py](Threema/threema_DB_decrypt.py) can do `Step1` and `Step2` process and extract the database decryption key.
- [threema_getMultimedia.py](Threema/threema_getMultimedia.py) can do `Step3` process and extract the multimedia decryption key. This file require the key from `Step2`.

### Verification
All these 3 messenger use `SQLCipher`, so we need PRAGMA values to success decryption. We listed PRAGMA values in Table 9.

---

# Change Logs
Whenever the decryption algorithm of these messengers changes, we will leave a note here.

- 2021.09.23 First commit
- 2021.12.26 Add description(code not changed)