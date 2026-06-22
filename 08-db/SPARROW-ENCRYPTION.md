# Sparrow Wallet File Encryption

## File Format (`.mv.db`)

The wallet file is an **H2 MVStore database** with AES encryption. Binary layout at the start of the file:

| Offset | Length | Content |
|--------|--------|---------|
| 0 | 10 bytes | `H2encrypt\n` — H2's own cipher header |
| 10 | 8 bytes | H2's internal salt |
| 18 | 6 bytes | `SPRW1\n` — Sparrow magic bytes |
| 24 | 16 bytes | **Argon2 salt** (random, per-wallet) |

## Key Derivation (KDF)

The user's password is processed by **Argon2id** with these parameters (`SPRW1_PARAMETERS`):

| Parameter | Value |
|-----------|-------|
| Variant | Argon2id |
| Salt length | 16 bytes (read from file at offset 24) |
| Hash output | 32 bytes |
| Iterations | 10 |
| Memory | 262 144 KiB (256 MB) |
| Parallelism | 4 |

## From KDF Output to H2 Password

1. Argon2id produces a **32-byte raw hash** — treated as a secp256k1 private key scalar
2. `ECKey.fromPrivate(hashBytes)` derives the corresponding secp256k1 keypair
3. The **33-byte compressed public key** is hex-encoded → 66-character hex string
4. That hex string is used as the **H2 database file password** (`CIPHER=AES`)

```
password  ──►  Argon2id(iterations=10, mem=256MB, par=4, salt[16])
                        │
                        ▼  32 bytes
              secp256k1 private key
                        │
                        ▼
              compressed public key (33 bytes)
                        │
                        ▼  hex-encode
              66-char hex string  ──►  H2 file password
```

## H2 AES Encryption

H2 is opened with `CIPHER=AES` in the JDBC URL. Password changes use `ChangeFileEncryption.execute(..., "AES", ...)`. H2 internally derives a **128-bit AES key** from the file password and uses **AES-CBC** to encrypt the database pages.

## "No Password" Case

When no user password is set, Sparrow uses a hardcoded fixed `NO_PASSWORD_KEY` (private key `885e5a09708a167ea356a252387aa7c4893d138d632e296df8fbf5c12798bd28`). The file is still AES-encrypted, but with a **publicly known fixed key** — effectively unencrypted in terms of security.

## Export

`Sparrow.exportWallet()` copies the wallet to a temp `.mv.db` file using the **same `encryptionPubKey` as the source wallet**. No re-keying occurs — the export file is encrypted identically to the live wallet file.

## Key Source References

- `DbPersistence.java` — `getWalletKeyDeriver()`, `getFilePassword()`, `updatePassword()`, `getUrl()`
- `Argon2KeyDeriver` — `SPRW1_PARAMETERS` static initializer, `deriveECKey()`
- `Storage.java:38` — `NO_PASSWORD_KEY` hardcoded value
- `Sparrow.java:31` — `exportWallet()` re-uses source encryption key
