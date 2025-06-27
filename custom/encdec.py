import custom.encryptionkey as encryptionkey
import custom.decryptionkey as decryptionkey
from flask_login import current_user

def encryptor(raw_uid, raw_pwd):
    enc = ""
    # Use user-specific salt if authenticated, otherwise fallback to default
    salt = current_user.unique_key[:8] if current_user.is_authenticated else "0h3rR0r5"
    enc += salt
    for i in range(len(raw_uid)):
        if i % 2 == 0:
            enc += encryptionkey.ASCII(raw_uid[i])
        else:
            enc += encryptionkey.bitconv(raw_uid[i])
    enc += salt
    for i in range(len(raw_pwd)):
        if i % 2 == 0:
            enc += encryptionkey.ASCII(raw_pwd[i])
        else:
            enc += encryptionkey.bitconv(raw_pwd[i])
    return enc[::-1]

def decryptor(rpwd):
    if not rpwd:
        return ""
    npwd = rpwd[::-1]
    dec_uid = ""
    dec_pwd = ""
    # Use user-specific salt if authenticated, otherwise fallback to default
    salt = current_user.unique_key[:8] if current_user.is_authenticated else "989"
    pwd = npwd[len(salt):]
    t = pwd.find(salt)
    flag = True
    toggle = 0

    i = 0
    while i < len(pwd):
        if i == t:
            i += len(salt)
            flag = False
            toggle = 0
        
        if flag:
            if toggle == 0:
                dec_uid += decryptionkey.CharfromASCII(pwd[i:i+3])
                i += 3
            else:
                dec_uid += decryptionkey.CharfromBit(pwd[i:i+7])
                i += 7
        else:
            if toggle == 0:
                dec_pwd += decryptionkey.CharfromASCII(pwd[i:i+3])
                i += 3
            else:
                dec_pwd += decryptionkey.CharfromBit(pwd[i:i+7])
                i += 7
        toggle = 1 - toggle
    
    return [dec_uid, dec_pwd]

if __name__ == "__main__":
    exit(0)