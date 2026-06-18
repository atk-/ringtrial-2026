#!/usr/bin/env python3
"""
h2db2john.py - Extract crackable hash from H2 MVStore encrypted database files (.mv.db)

Derived entirely from H2 source code (no existing tool was found):
  src/main/org/h2/store/fs/encrypt/FileEncrypt.java  - file layout, KDF
  src/main/org/h2/store/fs/encrypt/XTS.java           - cipher mode
  src/main/org/h2/security/AES.java                   - block cipher
  src/main/org/h2/security/SHA256.java                - PBKDF2 implementation
  src/main/org/h2/engine/ConnectionInfo.java           - password encoding
  src/main/org/h2/mvstore/FileStore.java               - MVStore header format
  src/main/org/h2/mvstore/DataUtils.java               - header serialisation

------------------------------------------------------------------------
FILE LAYOUT (FileEncrypt.java)
------------------------------------------------------------------------
  Offset     0 –     9 : magic "H2encrypt\\n"  (10 bytes, plaintext)
  Offset    10 –    17 : 8-byte random salt    (plaintext)
  Offset    18 –  4095 : header padding        (plaintext zeros)
  Offset  4096 –  8191 : encrypted sector 0   (4096 bytes, AES-128-XTS)
  Offset  8192 – 12287 : encrypted sector 1   (4096 bytes, AES-128-XTS)
  ...

------------------------------------------------------------------------
KEY DERIVATION (FileEncrypt.createXTS + SHA256.getPBKDF2)
------------------------------------------------------------------------
  key = PBKDF2-HMAC-SHA256(password_bytes, salt, iterations=10, dkLen=16)

  iterations=10 is deliberately low (comment in source: Android perf concern).

PASSWORD ENCODING (FilePathEncrypt.getPasswordBytes / ConnectionInfo)
------------------------------------------------------------------------
  JDBC with CIPHER=AES (most common):
      Connection URL: jdbc:h2:/path/to/db;CIPHER=AES
      Password field: "<file_password> <user_password>"  (space-separated)
      The file_password portion is encoded as UTF-16BE before PBKDF2.

  Direct encrypt: file-system scheme (rare):
      Path: encrypt:<password>:/path/to/db
      Password is taken as UTF-8 bytes.

  This script assumes the JDBC path (UTF-16BE). Use --utf8 for the other.

------------------------------------------------------------------------
XTS MODE (XTS.java) — IMPORTANT: H2 uses ONE key for BOTH data and tweak
------------------------------------------------------------------------
  Standard IEEE P1619 XTS uses two separate keys.
  H2 uses the single 16-byte derived key for both the data AES and the
  tweak AES.  Standard AES-XTS libraries will not work without adaptation.

  Decryption of block i within sector N:
      if i == 0:
          tweak = AES_ECB_encrypt(key, N as 16-byte little-endian)
      else:
          tweak = GF(2^128) left-shift (multiply by x) of previous tweak
      plaintext_block = AES_ECB_decrypt(key, ciphertext_block XOR tweak) XOR tweak

------------------------------------------------------------------------
VERIFICATION ORACLE
------------------------------------------------------------------------
  The MVStore file header (written by DataUtils.appendMap with keys sorted
  alphabetically) always begins with "H:2," because:
    - "H" (ASCII 72) sorts before all lowercase keys (a-z start at 97)
    - "H" maps to the integer 2 (format version), hex-encoded as "2"
  So the first 4 decrypted bytes of sector 0 are always: 0x48 0x3a 0x32 0x2c

------------------------------------------------------------------------
HASH FORMAT
------------------------------------------------------------------------
  <filename>:$h2$<iterations>$<salt_hex>$<sector0_block0_hex>

  salt_hex          : 16 hex chars (8 bytes)
  sector0_block0_hex: 32 hex chars (first 16 bytes of encrypted sector 0)

Usage:
  python3 h2db2john.py mydb.mv.db                    # extract hash
  python3 h2db2john.py mydb.mv.db --verify password  # test a password
  python3 h2db2john.py *.mv.db >> hashes.txt         # batch extract
"""

import sys
import os
import hashlib
import argparse

MAGIC            = b"H2encrypt\n"
MAGIC_LEN        = 10
SALT_OFFSET      = MAGIC_LEN          # 10
SALT_LENGTH      = 8
HEADER_LENGTH    = 4096               # FileEncrypt.BLOCK_SIZE == HEADER_LENGTH
HASH_ITERATIONS  = 10
SECTOR_SIZE      = 4096               # FileEncrypt.BLOCK_SIZE
AES_BLOCK        = 16
# Only the first AES block of sector 0 is needed for verification.
VERIFY_BYTES     = AES_BLOCK          # 16 bytes


# ---------------------------------------------------------------------------
# Hash extraction (no dependencies)
# ---------------------------------------------------------------------------

def extract_hash(filename):
    """
    Read filename, verify H2 magic, extract salt and the first 16 bytes of
    encrypted sector 0.  Returns the hash string, or None on error.
    """
    try:
        with open(filename, "rb") as fh:
            header = fh.read(HEADER_LENGTH)
            if len(header) < HEADER_LENGTH:
                _err(filename, "file too short for a full H2 header")
                return None
            if not header.startswith(MAGIC):
                _err(filename, "H2encrypt\\n magic not found — not an encrypted H2 MVStore file")
                return None
            salt = header[SALT_OFFSET : SALT_OFFSET + SALT_LENGTH]
            # Encrypted sector 0 begins immediately after the header.
            fh.seek(HEADER_LENGTH)
            block0 = fh.read(VERIFY_BYTES)
    except OSError as exc:
        _err(filename, str(exc))
        return None

    if len(block0) < VERIFY_BYTES:
        _err(filename, "no encrypted data after header")
        return None

    name = os.path.basename(filename)
    return f"{name}:$h2${HASH_ITERATIONS}${salt.hex()}${block0.hex()}"


# ---------------------------------------------------------------------------
# Password verification (requires pycryptodome: pip install pycryptodome)
# ---------------------------------------------------------------------------

def _xts_decrypt_block0_sector0(key_bytes, ciphertext_block):
    """
    Decrypt the first 16-byte AES block of sector 0 using H2's single-key XTS.

    H2 XTS (XTS.java):
      - initTweak(0): sector id 0 → 16 zero bytes → AES_encrypt(key, zeros) = tweak
      - Block 0 (i=0): updateTweak is NOT called before the first block
      - decrypt: temp = ct XOR tweak; pt = AES_decrypt(key, temp) XOR tweak
    """
    try:
        from Crypto.Cipher import AES as _AES
    except ImportError:
        print("pycryptodome is required for --verify (pip install pycryptodome)",
              file=sys.stderr)
        return None

    enc = _AES.new(key_bytes, _AES.MODE_ECB)
    dec = _AES.new(key_bytes, _AES.MODE_ECB)

    # tweak for sector 0: AES_encrypt(key, 16 zero bytes)
    tweak = enc.encrypt(bytes(AES_BLOCK))

    temp      = bytes(a ^ b for a, b in zip(ciphertext_block, tweak))
    plaintext = bytes(a ^ b for a, b in zip(dec.decrypt(temp), tweak))
    return plaintext


def verify_password(filename, password, utf8=False):
    """
    Try password against filename.  Returns True if correct, False otherwise.
    Prints a diagnostic line either way.
    """
    try:
        with open(filename, "rb") as fh:
            header = fh.read(HEADER_LENGTH)
            fh.seek(HEADER_LENGTH)
            block0 = fh.read(VERIFY_BYTES)
    except OSError as exc:
        _err(filename, str(exc))
        return False

    if not header.startswith(MAGIC):
        _err(filename, "not an encrypted H2 MVStore file")
        return False

    salt = header[SALT_OFFSET : SALT_OFFSET + SALT_LENGTH]

    # Encode password the same way H2 does.
    if utf8:
        pw_bytes = password.encode("utf-8")
    else:
        # UTF-16BE: high byte first, matches FilePathEncrypt.getPasswordBytes()
        pw_bytes = password.encode("utf-16-be")

    key = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, HASH_ITERATIONS, dklen=16)

    plaintext = _xts_decrypt_block0_sector0(key, block0)
    if plaintext is None:
        return False  # import error already printed

    # MVStore header always starts with "H:2," (DataUtils.appendMap, keys sorted).
    ORACLE = b"H:2,"
    if plaintext[:len(ORACLE)] == ORACLE:
        print(f"{filename}: password CORRECT — decrypted header starts with {ORACLE!r}")
        return True
    else:
        print(f"{filename}: password WRONG — decrypted first bytes: {plaintext[:8].hex()}")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _err(filename, msg):
    print(f"{os.path.basename(filename)}: {msg}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Extract H2 MVStore (.mv.db) password hash for offline cracking.",
        epilog="""
Examples:
  %(prog)s mydb.mv.db
  %(prog)s mydb.mv.db --verify 'secretpassword'
  %(prog)s *.mv.db >> hashes.txt
  %(prog)s mydb.mv.db --verify 'pass' --utf8   # if opened via encrypt: scheme
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="+", metavar="FILE",
                        help="Encrypted H2 MVStore database file(s) (.mv.db)")
    parser.add_argument("--verify", metavar="PASSWORD",
                        help="Test a known password instead of printing the hash "
                             "(requires pycryptodome)")
    parser.add_argument("--utf8", action="store_true",
                        help="Encode the password as UTF-8 instead of UTF-16BE "
                             "(use when the DB was opened via the encrypt: file-system "
                             "scheme rather than a JDBC CIPHER=AES connection)")
    args = parser.parse_args()

    rc = 0
    for filename in args.files:
        if args.verify is not None:
            if not verify_password(filename, args.verify, utf8=args.utf8):
                rc = 1
        else:
            result = extract_hash(filename)
            if result:
                print(result)
            else:
                rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
