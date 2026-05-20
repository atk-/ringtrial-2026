#!/usr/bin/env python3
"""
Crack the Syncthing encrypted folder password by brute-forcing the token.

Scheme:
  folderKey = scrypt(password, salt="syncthing"+folderID, N=32768, r=8, p=1, dklen=32)
  token     = AES-SIV(key=folderKey, plaintext="syncthing"+folderID)
"""

import argparse
import base64
import hashlib
import json
import sys
import time
import multiprocessing as mp
from pathlib import Path
from Crypto.Cipher import AES

TEST_FOLDER_ID  = "vkr3n-mw7xp"
TEST_SALT       = b"syncthing" + TEST_FOLDER_ID.encode()   # b"syncthinkvkr3n-mw7xp"

SALT = None
CIPHERTEXT = None
TAG = None

# TOKEN_PATH = Path(__file__).parent / "token.bin"

# TOKEN_BYTES = TOKEN_PATH.read_bytes()   # 36 bytes: tag(16) || ciphertext(20)
# TAG        = TOKEN_BYTES[:16]
# CIPHERTEXT = TOKEN_BYTES[16:]

SCRYPT_MEM = 64 * 1024 * 1024  # 64 MB

def check(password: str) -> bool:
    key = hashlib.scrypt(
        password.encode(),
        salt=SALT,
        n=32768, r=8, p=1, dklen=32,
        maxmem=SCRYPT_MEM,
    )
    try:
        # miscreant passes a nil nonce as one empty S2V component — match
        # that by calling update(b"") before decrypt (see miscreant aead.go:89)
        c = AES.new(key, AES.MODE_SIV)
        c.update(b"")
        result = c.decrypt_and_verify(CIPHERTEXT, TAG)
        return result == SALT 
    except (ValueError, KeyError):
        return False

def worker(batch: list[str]) -> str | None:
    for pw in batch:
        if check(pw):
            return pw
    return None

def variants(word):
    suffixes = ['87', '1987', '84', '1984', '86', '1986', '!', 'suxx!']
    suffixes = ['']
    ret = [word + s for s in suffixes]
    ret += [word.lower() + s for s in suffixes]

    import random
    random.shuffle(ret)

    return ret

def load_wordlist(path: str) -> list[str]:
    words: list[str] = []
    for line in Path(path).read_text(errors="replace").splitlines():
        w = line.strip()
        if w:
            words.extend(variants(w))

    print(words[:10] + words[-10:])
    return words

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('working_dir', type=str)
    parser.add_argument('wordlist', type=str)

    args = parser.parse_args()

    # Sanity-check: Python output must match Go/miscreant reference for known input
    _key = hashlib.scrypt(b"testpassword", salt=TEST_SALT, n=32768, r=8, p=1, dklen=32, maxmem=SCRYPT_MEM)
    _go  = bytes.fromhex("a5ac06fc76633e1a8cdea30b79d6be38a881f9611a82964b4f890215c592f646b68d2bbf")
    _c   = AES.new(_key, AES.MODE_SIV); _c.update(b"")
    _ct, _tag = _c.encrypt_and_digest(TEST_SALT)

    assert _tag + _ct == _go, "AES-SIV output does not match Go/miscreant reference"

    words = load_wordlist(args.wordlist)
    print(f"Loaded {len(words)} words from {args.wordlist}", flush=True)

    # find the folder id and token from the working directory
    tokenfile = Path(args.working_dir) / '.stfolder' / 'syncthing-encryption_password_token'
    print(tokenfile)

    tokendata = json.load(open(tokenfile, 'r'))
    print(tokendata)

    folder_id = tokendata['FolderID']
    token = base64.b64decode(tokendata['Token'])
    
    global SALT, TAG, CIPHERTEXT
    SALT = b'syncthing' + folder_id.encode()
    TAG = token[:16]
    CIPHERTEXT = token[16:]

    cpus   = mp.cpu_count()
    batch  = 64  # passwords per chunk sent to a worker
    found  = None
    done   = 0
    t0     = time.perf_counter()

    print(f"Starting search with {cpus} workers...", flush=True)

    candidates = words
    total      = len(candidates)
    chunks     = [candidates[i:i+batch] for i in range(0, total, batch)]

    with mp.Pool(cpus) as pool:
        for result in pool.imap_unordered(worker, chunks, chunksize=1):
            done += batch
            if result:
                found = result
                pool.terminate()
                break
            if done % 500 < batch:
                elapsed = time.perf_counter() - t0
                rate    = done / elapsed
                remaining = (total - done) / rate if rate else 0
                print(f"  {done}/{total}  {rate:.0f} pw/s  ETA {remaining:.0f}s", flush=True)

    if found:
        print(f"\n*** PASSWORD FOUND: {found!r} ***")
    else:
        print("\nPassword not found in wordlists.")
    print(f"Elapsed: {time.perf_counter()-t0:.1f}s")

if __name__ == "__main__":
    main()
