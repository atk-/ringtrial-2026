# H2 Database Encryption

This document describes how H2 encrypts database files, derived from reading
the H2 source code directly. All file and line references are relative to
`src/main/org/h2/`.

---

## Two Encryption Subsystems

H2 has two separate encryption subsystems, one per storage engine:

| Engine | File extension | Cipher mode | Key derivation |
|---|---|---|---|
| MVStore (modern, default) | `.mv.db` | AES-128-XTS | PBKDF2-HMAC-SHA256 |
| PageStore (legacy) | `.h2.db` | AES / XTEA / FOG (selectable) | SHA-256 + iterations |

---

## MVStore Encryption (`.mv.db`)

### Relevant source files

- `store/fs/encrypt/FileEncrypt.java` — file layout, key derivation, read/write
- `store/fs/encrypt/XTS.java` — XTS cipher mode
- `store/fs/encrypt/FilePathEncrypt.java` — `encrypt:` file-system scheme, password encoding
- `security/AES.java` — AES-128 block cipher (pure Java, no JCE)
- `security/SHA256.java` — PBKDF2-HMAC-SHA256 implementation
- `engine/ConnectionInfo.java` — password splitting and encoding for JDBC connections

### Activating encryption

Encryption is activated by including `CIPHER=AES` in the JDBC URL. The
password field must then contain two passwords separated by a single space:

```
jdbc:h2:/path/to/mydb;CIPHER=AES
Username: sa
Password: filepassword userpassword
```

The part before the space is the file encryption password. The part after is
the normal database user password. This splitting happens in
`ConnectionInfo.convertPasswords()`.

### File layout

(`FileEncrypt.java`, constants `HEADER_LENGTH`, `BLOCK_SIZE`, `SALT_POS`, `SALT_LENGTH`)

```
Offset       Length   Content
-----------  -------  -----------------------------------------------
0            10       Magic: "H2encrypt\n"  (ISO-8859-1, plaintext)
10           8        Random salt           (plaintext)
18           4078     Header padding        (zero bytes, plaintext)
4096         4096     Encrypted sector 0
8192         4096     Encrypted sector 1
...
```

The first 4096 bytes form a plaintext header (`HEADER_LENGTH = BLOCK_SIZE = 4096`).
Every 4096-byte block after offset 4096 is an independently encrypted sector.
The logical file size visible to the MVStore engine is the physical size minus
4096 (the header).

### Password encoding

How the file password is converted to bytes depends on how the database is
opened.

**JDBC `CIPHER=AES` connection** (common path — `ConnectionInfo.convertPasswords` →
`FilePathEncrypt.getPasswordBytes`):

```
password chars  →  UTF-16BE bytes  →  PBKDF2
```

Each `char` becomes two bytes, high byte first. For the ASCII password `"abc"`:
```
0x00 0x61  0x00 0x62  0x00 0x63
```

**`encrypt:` file-system scheme** (rare — `FilePathEncrypt.open`):

```
password string  →  UTF-8 bytes  →  PBKDF2
```

The encoding is not recorded in the file. A cracking tool must try both if the
origin is unknown.

### Key derivation

(`FileEncrypt.createXTS`, `SHA256.getPBKDF2`)

On first open of a new file, an 8-byte salt is generated with
`MathUtils.secureRandomBytes` and written at offset 10. On subsequent opens,
the salt is read from that position.

```
key = PBKDF2-HMAC-SHA256(password_bytes, salt, iterations=10, dkLen=16)
```

The resulting 16-byte key is used directly as the AES-128 key.
After key derivation the raw password bytes are zeroed and discarded
(`encryptionKey = null`).

**The iteration count of 10 is intentionally very low.** A comment in the
source attributes this to Android performance constraints. It makes the
derived key trivially fast to brute-force on modern hardware.

### XTS cipher mode

(`XTS.java`)

H2 implements XTS as described in IEEE P1619. Each 4096-byte sector is
encrypted independently using the sector's zero-based index as the tweak input.

**Critical difference from standard XTS**: IEEE P1619 requires two independent
keys of equal length — one for data encryption and one for tweak encryption.
H2 uses the single 16-byte derived key for both. Standard AES-XTS library
implementations (OpenSSL, pycryptodome's `MODE_XTS`, etc.) will not produce
compatible output without modification.

#### Tweak derivation

```
tweak₀ = AES_ECB_encrypt(key, sector_id_as_16_bytes_little_endian)
```

`sector_id` is written into the tweak buffer one byte at a time with
`id >>>= 8` (unsigned right shift), giving little-endian layout. For sector 0,
the tweak input is 16 zero bytes.

Between consecutive 16-byte blocks within a sector, the tweak is updated by
multiplication by `x` in GF(2¹²⁸) with feedback polynomial `0x87`:

```java
// XTS.updateTweak — left-shift by 1 bit, XOR 0x87 into byte 0 if carry
```

The tweak update is **not** applied before the first block (`i == 0`) within a
sector.

#### Encryption of one block (i > 0 shown for completeness)

```
if i == 0: tweak = tweak₀
else:       tweak = GF_leftshift(prev_tweak)

ciphertext_block = (AES_ECB_encrypt(key, plaintext_block XOR tweak)) XOR tweak
```

Decryption reverses the inner step:

```
plaintext_block = (AES_ECB_decrypt(key, ciphertext_block XOR tweak)) XOR tweak
```

#### Partial last block (ciphertext stealing)

If the last sector is not a multiple of 16 bytes, H2 uses ciphertext stealing
(`XTS.swap`): the final partial block swaps bytes with the preceding full block
before the last encrypt/decrypt step.

### Verification oracle

There is no HMAC or authentication tag over the file. H2 verifies the password
implicitly: if decryption produces garbage, MVStore fails to parse its own
header and throws an error.

For offline cracking the verification oracle is the MVStore file header, which
is always the first data in sector 0. `DataUtils.appendMap` serialises the
header as a comma-separated `key:value` string with keys sorted
lexicographically. Because `"H"` (ASCII 72) sorts before all lowercase letters
(a–z start at 97), the header always begins:

```
H:2,block:...
```

The first four decrypted bytes of sector 0 are always `0x48 0x3a 0x32 0x2c`
(`H`, `:`, `2`, `,`). This is sufficient to confirm a correct key with
negligible false-positive probability.

---

## PageStore Encryption (`.h2.db`)

### Relevant source files

- `security/SecureFileStore.java` — read/write with encryption
- `security/CipherFactory.java` — cipher selection
- `security/AES.java`, `security/XTEA.java`, `security/Fog.java` — block ciphers
- `engine/Constants.java` — `FILE_BLOCK_SIZE = 16`

### Activating encryption

Same JDBC mechanism as MVStore: `CIPHER=AES` (or `CIPHER=XTEA`) in the URL
with a space-separated password. The cipher name is stored as a database
setting and must match on every subsequent open.

### Available ciphers

`CipherFactory.getBlockCipher` accepts three algorithm names:

| Name | Description |
|---|---|
| `AES` | AES-128, pure Java implementation |
| `XTEA` | 64-round XTEA block cipher |
| `FOG` | XOR "obfuscation" — no cryptographic security, documented as such |

`FOG` should never be used for real data protection.

### Key derivation

(`SecureFileStore.initKey`, `SHA256.getHashWithSalt`, `SHA256.getHash`)

```
k₀  = SHA-256(password_bytes || salt)
kᵢ  = SHA-256(kᵢ₋₁)   for i = 1 … keyIterations   (default ~1024)
key = kᵢ

iv_key = SHA-256(key)
```

Two keys are derived: `key` for encrypting data, `iv_key` for generating the
per-block initialisation vectors. Both use the same cipher algorithm.

The salt is `FILE_BLOCK_SIZE` (16) random bytes, stored at the start of the
file in plaintext.

### Encryption mode

(`SecureFileStore.write`, `SecureFileStore.xorInitVector`)

H2 uses a custom mode that resembles CTR/OFB:

1. For each 16-byte chunk at file position `p`, compute an IV by
   AES-encrypting (with `iv_key`) the value `p / 8` encoded as big-endian
   64-bit integers across the 16-byte IV buffer.
2. XOR the plaintext with the IV.
3. Apply the data cipher in ECB mode.

Because the IV is position-derived rather than chained, reads and writes can
be performed at arbitrary offsets without processing the entire file.

### Security comparison

| Property | MVStore | PageStore |
|---|---|---|
| KDF | PBKDF2-HMAC-SHA256 | SHA-256 iterated |
| KDF iterations | **10** (very low) | ~1024 |
| Salt length | 8 bytes | 16 bytes |
| Mode | XTS (sector-based) | Custom CTR-like |
| Authentication | None | None |
| Weakest point | 10-iteration KDF | Custom mode, no authentication |

Neither engine authenticates the ciphertext. An attacker with write access to
the file can modify encrypted data without detection.

---

## Network Encryption (TLS)

Separate from file encryption, H2's TCP server supports TLS for connections.
`security/CipherFactory.java` handles SSL socket creation and ships a
hard-coded self-signed RSA certificate (stored as hex literals in the source)
used when no external keystore is configured. SSL protocol versions are
disabled; only TLS is permitted.

---

## Cracking Considerations

The MVStore scheme is the realistic target:

- **Salt**: 8 bytes, stored in plaintext at file offset 10.
- **KDF cost**: PBKDF2-HMAC-SHA256 with only 10 iterations — effectively
  unthrottled on GPU hardware.
- **Verification**: first 4 bytes of decrypted sector 0 must equal `H:2,`.
- **No existing public tool was found** at time of writing (2026-06-17). The
  extraction script `h2db2john.py` in this repository implements the full
  extraction and optional password verification from first principles.

The PageStore scheme is slower to crack due to ~1024 SHA-256 iterations, but
is also unthrottled compared to modern KDFs (bcrypt, scrypt, Argon2).
