# bruteforce_stefano.py
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Given from the PDF (exact values)
salt = b"\x9aF\xdb^\xd5\x18\xb0\xe2k\r\xfc\xf3\x7f3\xe0\xb5"

ciphertext = b'gAAAAABlJ678-7eprVhp3wnTslVPcDZzK33bXpQ8WTctjUI8mTobjVwYa7LQfASyRzD2rh1RkB8ufPKsL-xHJyYaUGJa-dDi8wzx2XQzYV6dnnwbw1NJWxsfeb_Ol9_DhGcxQMm8nqjZw-6JHzR3_YtQpiZ4083_btWasC_Jg1EEjupDRp0-vXTwuTuwgYWMLlxwyFox9pCabsieEasHhb8mJFeBhw7xCDbUlLEJLPeUalSUSSv1JuA='

base_name = "Stefano"   # base name from the hint

digits = "0123456789"
lowercase = "abcdefghijklmnopqrstuvwxyz"

# PBKDF2 parameters (as in the PDF)
iterations = 100000
length = 32

def derive_key(password_bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def try_decrypt(candidate_password):
    passwd_bytes = candidate_password.encode('utf-8')
    key = derive_key(passwd_bytes)
    f = Fernet(key)
    try:
        clear = f.decrypt(ciphertext)
        return clear
    except Exception:
        return None

def generate_and_test():
    base = base_name
    tried = 0
    # Insert digit first, then letter (we will also cover letter-first by different insertion orders)
    for d in digits:
        for l in lowercase:
            # Insert digit at all positions, then insert letter at all positions of the new string
            for pos_d in range(len(base) + 1):
                s_with_d = base[:pos_d] + d + base[pos_d:]
                for pos_l in range(len(s_with_d) + 1):
                    candidate = s_with_d[:pos_l] + l + s_with_d[pos_l:]
                    tried += 1
                    if tried % 2000 == 0:
                        print(f"tried {tried} candidates, current: {candidate}")
                    clear = try_decrypt(candidate)
                    if clear is not None:
                        print("\n*** SUCCESS ***")
                        print("Password found:", candidate)
                        print("Decrypted plaintext:", clear.decode('utf-8', errors='replace'))
                        return candidate, clear
    # Also try letter inserted first, then digit (this is redundant for completeness but safe)
    for l in lowercase:
        for d in digits:
            for pos_l in range(len(base) + 1):
                s_with_l = base[:pos_l] + l + base[pos_l:]
                for pos_d in range(len(s_with_l) + 1):
                    candidate = s_with_l[:pos_d] + d + s_with_l[pos_d:]
                    tried += 1
                    if tried % 2000 == 0:
                        print(f"tried {tried} candidates, current: {candidate}")
                    clear = try_decrypt(candidate)
                    if clear is not None:
                        print("\n*** SUCCESS ***")
                        print("Password found:", candidate)
                        print("Decrypted plaintext:", clear.decode('utf-8', errors='replace'))
                        return candidate, clear

    print("Finished — password not found in generated search space.")
    return None, None

if __name__ == "__main__":
    print("Starting brute force...")
    pw, clear = generate_and_test()
    if pw is None:
        print("No password found. Consider whether the hint or allowed characters are different.")
    else:
        print("Done.")
