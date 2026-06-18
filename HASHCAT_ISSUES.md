# Hashcat Kernel Development — Issues and Solutions

Lessons learned writing a from-scratch scrypt+AES-SIV hashcat module (mode 86100).
These issues are not documented in hashcat's source or wiki and cost significant debugging time.

---

## 1. Stale compiled kernel cache silently overrides source edits

**Symptom**: Edits to `OpenCL/m86100-pure.cl` have no effect.  Adding `printf` statements produces no output.  Introducing deliberate syntax errors doesn't cause compilation to fail.

**Cause**: Hashcat compiles kernels once and caches them as pre-built binaries in `<hashcat_dir>/kernels/`.  On subsequent runs it loads the cached binary directly, never re-reading the `.cl` source.  The cache filename includes a hash of the *source content at compile time*, not of the current source.

The file looks like:
```
hashcat/kernels/m86100-pure.c3d6cbf1.kernel
```

**Discovery**: `strace -e trace=openat ./hashcat ...` showed the kernel path being opened.

**Solution**: Delete the stale `.kernel` file before every run while iterating:
```bash
rm -f ~/hashcat/kernels/m86100-*.kernel
./hashcat -m 86100 ...
```

Alternatively, use `strace` to confirm which file hashcat is actually reading before wasting time editing source:
```bash
strace -e trace=openat ./hashcat -m 86100 ... 2>&1 | grep -E "86100|m86100"
```

---

## 2. `hex_to_u32` returns a byte-swapped (LE) value — not a big-endian parse

**Symptom**: `module_hash_encode` outputs byte-swapped hex compared to the original hash string.  E.g. input `a5ac06fc` → output `fc06aca5`.

**Cause**: Hashcat's `hex_to_u32(buf)` does NOT parse `"a5ac06fc"` as `0xa5ac06fc`.  It interprets the first two hex chars as the *least significant byte*:

```c
// src/convert.c
v |= ((u32) hex_convert (hex[1]) <<  0);
v |= ((u32) hex_convert (hex[0]) <<  4);
v |= ((u32) hex_convert (hex[3]) <<  8);
v |= ((u32) hex_convert (hex[2]) << 12);
// ...
```

So `hex_to_u32("a5ac06fc")` = `0xfc06aca5` = `byte_swap_32(0xa5ac06fc)`.

This applies to **every** field stored via `hex_to_u32` — digest words AND esalt words.

**Solution**: In `module_hash_encode`, apply `byte_swap_32()` to every field that was decoded with `hex_to_u32()`:

```c
// For digest words:
byte_swap_32(digest[0]),  // recovers original hex "a5ac06fc"

// For esalt words decoded with hex_to_u32:
byte_swap_32(syncthing->ct[0]),
```

**Corollary for digest comparison**: Because `hex_to_u32` already gives the LE u32 form, the kernel's `r0..r3` (output of `aes128_encrypt`, also LE u32) compare directly with `digest[0..3]` via `COMPARE_M` — no extra swap needed in the comp kernel.

---

## 3. `aes128_set_encrypt_key` (lowercase) vs `AES128_set_encrypt_key` (uppercase) — different input conventions

**Symptom**: AES-SIV produces wrong output when the key setup mirrors m28200's `hc_swap32_S(out[i])` pattern.

**Cause**: Two different AES key-setup functions with opposite byte-order expectations:

| Function | Expects | Internal action |
|---|---|---|
| `aes128_set_encrypt_key` (lowercase) | LE u32 | swaps once to BE, then expands |
| `AES128_set_encrypt_key` (uppercase) | BE u32 | swaps once to LE, calls lowercase (= two swaps total) |

Module m28200 uses `AES256_set_encrypt_key` (uppercase) and therefore pre-swaps its key with `hc_swap32_S(out[i])`.  If you copy that pattern but call the lowercase function, the key is double-swapped and wrong.

**Rule**: 
- `scrypt_pbkdf2_ggp` output is LE u32.
- Pass it **directly** (no swap) to lowercase `aes128_set_encrypt_key`.
- Only swap if calling the uppercase `AES128_set_encrypt_key` / `AES256_set_encrypt_key`.

```c
// CORRECT:
u32 ks[44];
aes128_set_encrypt_key(ks, out, s_te0, s_te1, s_te2, s_te3);  // out is LE u32 from scrypt

// WRONG (copies m28200 pattern but uses lowercase function):
u32 ukey[4];
ukey[0] = hc_swap32_S(out[0]);  // over-swaps
aes128_set_encrypt_key(ks, ukey, s_te0, s_te1, s_te2, s_te3);
```

---

## 4. `aes128_encrypt` I/O is LE u32 (not raw bytes, not BE)

Both the input and output of `aes128_encrypt` are in **LE u32** format:
- Input `in[i]` is swapped to BE internally before AES operates.
- Output is swapped back to LE before returning.

This means:
- A zero block is passed as `{0, 0, 0, 0}` (same in any byte order).
- The returned ciphertext is LE u32: if AES output bytes are `a5 ac 06 fc ...`, then `out[0] = 0xfc06aca5`.
- The CMAC subkey generation (`make_kn`) and all XOR operations work directly on these LE u32 values.

**No extra swapping is needed** between `aes128_set_encrypt_key` and `aes128_encrypt` calls.

---

## 5. `make_kn` operates on LE u32 and is correct for CMAC doubling

The `make_kn` function copied from `m22001-pure.cl` doubles a 128-bit GF(2^128) element stored as four LE u32 words.  In LE u32, the "first byte" of the 16-byte block (the MSB in GF convention) is bits 0–7 of `k[0]`, so:

```c
const u32 c = kr[0] & 1;     // bit 7 of byte[0] = MSB of GF element
k[3] ^= c * 0x87000000;      // XOR 0x87 into byte[15] (last byte in LE layout)
```

This is mathematically equivalent to the big-endian `dbl()` used in Python/Go reference code.  **Do not transpose the XOR constant** — `0x87000000` is correct (byte[12]=0, byte[13]=0, byte[14]=0, byte[15]=0x87 in the u32's memory layout).

---

## 6. CMAC padding byte positions in LE u32

When padding a partial block for CMAC (ISO/IEC 7816-4: append 0x80 then zeros), the byte positions map to LE u32 as follows:

- **Padding 0x80 at byte offset 0** (empty message or first byte of a block): `word[0] = 0x00000080` (0x80 is the LSByte).
- **Padding 0x80 at byte offset 4** (4-byte partial block followed by 12 zero bytes):
  - `word[0]` = the 4 data bytes (as LE u32)
  - `word[1] = 0x00000080` (0x80 at byte[4] = LSByte of word[1])
  - `word[2] = 0`, `word[3] = 0`

A common mistake is writing `0x80000000` (which places 0x80 at the MSByte / byte offset 3, not offset 0).

---

## 7. S2V xorend: XOR into the LAST 16 bytes, not the first

For `xorend(Sn, D)` where Sn is 20 bytes (5 LE u32 words) and D is 16 bytes (4 LE u32 words):

```
XOR D into bytes [4..19] of Sn, leaving bytes [0..3] unchanged.

T[0] = msg[0]           // bytes 0-3: unchanged
T[1] = msg[1] ^ D[0]   // bytes 4-7
T[2] = msg[2] ^ D[1]   // bytes 8-11
T[3] = msg[3] ^ D[2]   // bytes 12-15
T[4] = msg[4] ^ D[3]   // bytes 16-19
```

The "last 16 bytes" = words 1–4 (not words 0–3).  A 20-byte message does NOT align the XOR at word zero.

---

## 8. `SCRYPT_THREADS` must be named exactly that

`src/modules/scrypt_common.c` references the constant `SCRYPT_THREADS` by that exact name.  Defining it as `SYNCTHING_SCRYPT_THREADS` or any variant causes a compile error like:

```
error: 'SCRYPT_THREADS' undeclared
```

**Solution**:
```c
static const u32 SCRYPT_THREADS = 4;
#include "scrypt_common.c"
```

The value 4 is the standard for scrypt modules; change it only if you have a specific reason.

---

## 9. scrypt salt is stored raw (no byte-swap) in `salt->salt_buf`

When building the scrypt salt directly in `module_hash_decode` via `memcpy`:

```c
u8 *salt_bytes = (u8 *) salt->salt_buf;
memcpy(salt_bytes, "syncthing", 9);
memcpy(salt_bytes + 9, folder_id, folder_id_len);
salt->salt_len = 9 + folder_id_len;
```

The salt bytes are stored as-is in LE u32 packing (first byte = LSByte of `salt_buf[0]`).  The GPU-side `scrypt_pbkdf2_ggg` reads with `sha256_hmac_update_global_swap`, which applies `hc_swap32_S` per word before SHA-256 processes them — so the byte order is correct end-to-end.

The same `salt_buf` pointer is safe to pass directly to `syncthing_s2v` (or equivalent) as a 20-byte LE u32 message, because `aes128_encrypt` also uses LE u32 convention.

---

## 10. `--self-test-disable` takes no argument

```bash
# WRONG:
./hashcat -m 86100 --self-test-disable=0 ...

# CORRECT:
./hashcat -m 86100 --self-test-disable ...
```

The flag is a boolean switch.  Passing `=0` causes "option doesn't allow an argument" error.

---

## 11. `check_header_0512` key swap: SHA256 needs it, BLAKE2s does NOT

When adapting a SHA256 VeraCrypt kernel (e.g. `m13751-pure.cl`) to a BLAKE2s kernel, the
`check_header_0512` function contains:

```c
key1[0] = hc_swap32_S (key[ 0]);
// ...
key2[7] = hc_swap32_S (key[15]);
```

**Symptom**: Self-test and known-password crack both silently fail — 500 000 iterations run
but no hash matches. No error message.

**Cause**: SHA256 stores its output as BE u32, so the swap converts BE→LE before passing the
key to the XTS cipher (which expects LE). BLAKE2s stores its output as LE u32 already. Applying
`hc_swap32_S` to a LE value byte-reverses each 4-byte group, producing a completely wrong key.

**Fix**: In the BLAKE2s kernel's `check_header_0512`, remove all `hc_swap32_S` calls:

```c
// BLAKE2s output is already LE u32 — cipher expects LE — no swap needed.
key1[0] = key[ 0];
// ...
key2[7] = key[15];
```

This applies to `check_header_0512` (XTS-512) and analogously to any other `check_header_*`
variants in the kernel.

---

---

## 12. `argon2_final` in `inc_hash_argon2.cl` silently truncates output at 64 bytes

**Symptom**: Mode with `digest_len = 192` runs to completion, GPU at 100%, but never finds a match — even with a known-correct password.

**Cause**: `argon2_final` hardcodes `0x01010040` as the Blake2b parameter word, which encodes a 64-byte (0x40) output regardless of `options->digest_len`. The output loop then reads `ctx.h[idx]` for `idx = 8..23`, which overflows into `ctx.m[]` — returning garbage or zeros for bytes 64–191.

**Fix**: For `digest_len > 64`, implement the RFC 9106 §3.2 Blake2b-long (H') chain manually:

```
A0 = Blake2b-64(le32(T) || XOR_last_blocks)  → take first 32 bytes
A1 = Blake2b-64(A0)                           → take first 32 bytes
A2 = Blake2b-64(A1)                           → take first 32 bytes
A3 = Blake2b-64(A2)                           → take first 32 bytes
Afin = Blake2b-64(A3)                         → take all 64 bytes
Total: 32+32+32+32+64 = 192 bytes
```

For T = 192, implement as `argon2_final_192` (inline in the kernel file) rather than patching `inc_hash_argon2.cl`. The standard `argon2_final` is fine for all existing modes (digest_len ≤ 64).

**rem sliding-window**: The XOR'd last blocks are 1024 bytes = 128 u64 words. The Blake2b context holds 16 u64 words at a time. To prepend `le32(T)` without buffering, use the "rem" trick: carry the displaced high u32 forward into the next slot:

```opencl
u32 rem = T;   // = 192
for each u64 ctx.m[idx]:
    const u64 value = ctx.m[idx];          // current XOR word
    ctx.m[idx] = hl32_to_64_S(l32_from_64_S(value), rem);  // slide rem into low half
    rem = h32_from_64_S(value);            // carry displaced high half
```

After all 128 words, flush the final carry: `ctx.m[0] = hl32_to_64_S(0, rem)` then transform with `BLAKE2B_FINAL`.

---

## 13. `hl32_to_64_S(a, b)` — first argument is HIGH half (bytes 4–7), second is LOW half (bytes 0–3)

**Symptom**: Blake2b intermediate results are completely wrong when loading `u32` pairs back into a `u64` context, even though the logic looks correct.

**Cause**: The name suggests "high-low", but the implementation is:

```c
// inc_common.cl:
hl32_to_64_S(a, b) → v64_from_v32ab_S(b, a)
    where v.v32.a = b  (LOW half, bytes 0–3)
          v.v32.b = a  (HIGH half, bytes 4–7)
```

So `hl32_to_64_S(a, b)`:  **a → bytes 4–7 (HIGH)**, **b → bytes 0–3 (LOW)**.

`l32_from_64_S(v)` = LOW half = bytes 0–3.  
`h32_from_64_S(v)` = HIGH half = bytes 4–7.

When packing two `u32` words back into a `u64` for a Blake2b message block:

```opencl
// If Ak[i*2] holds bytes 0-3 (LOW) and Ak[i*2+1] holds bytes 4-7 (HIGH):
ctx.m[i] = hl32_to_64_S(Ak[i*2+1], Ak[i*2]);   // HIGH first, LOW second  ✓

// WRONG (swaps every u64 — subtle because no compile error):
ctx.m[i] = hl32_to_64_S(Ak[i*2], Ak[i*2+1]);   // LOW first, HIGH second  ✗
```

Similarly when extracting:
```opencl
Ak[i*2+0] = l32_from_64_S(ctx.h[i]);   // bytes 0-3 → LOW half
Ak[i*2+1] = h32_from_64_S(ctx.h[i]);   // bytes 4-7 → HIGH half
```

**Rule of thumb**: Think of `hl32_to_64_S` as `(high_word, low_word)` — the first argument goes into the high (most significant) position.

---

## 14. `argon2_common.c` must be `#include`d inside the module `.c` file; `merged_options_t` must precede it

**Symptom**: Linker error (`undefined reference to argon2_module_extra_buffer_size`) or segfault when the esalt is cast to `merged_options_t *`.

**Cause**: `argon2_common.c` is NOT a separately compiled translation unit — it is designed to be `#include`d directly into the module's `.c` file, after the `merged_options_t` typedef. The file casts the esalt pointer to `merged_options_t *` and accesses `->argon2_options` at offset 0.

**Fix**:

```c
// In module_34xxx.c — ORDER MATTERS:

#include "argon2_common.h"          // 1. get argon2_options_t and helpers

typedef struct merged_options {
    argon2_options_t argon2_options;  // MUST be first field (offset 0)
    u32 data_buf[112];                // esalt-specific fields follow
    u32 signature;
} merged_options_t;

#include "argon2_common.c"          // 2. include AFTER merged_options_t is defined
```

If `merged_options_t` is defined after the `#include`, `argon2_common.c` sees an incomplete type and the cast produces undefined behaviour.

---

## 15. Argon2 VeraCrypt: no `hc_swap32_S` on keys (same rule as BLAKE2s, issue 11)

Argon2 produces LE u32 output, exactly like BLAKE2s. In any `check_header_*` function adapted from a SHA256 VeraCrypt kernel, remove all `hc_swap32_S` calls:

```opencl
// Argon2 output is LE u32 — XTS cipher expects LE — no swap.
key1[0] = key[ 0];   // NOT hc_swap32_S(key[0])
```

This applies to both `check_header_0512` (XTS-512) and `check_header_1536` (XTS-1536 triple-cascade).

---

## 16. `sha256_hmac_update_global_swap` over-reads 64 bytes on short salts

**Context**: mode 35900 uses an 8-byte salt stored via `memcpy` into `salt->salt_buf`.

**Symptom**: Random crashes or incorrect results when passing the global salt pointer directly to `sha256_hmac_update_global_swap` with `len = 8`. The function reads a full 64-byte block from `GLOBAL_AS` memory regardless of `len`, so it over-reads into adjacent salt slots or uninitialized memory.

**Fix**: Copy the salt words into a zero-padded private array and call `sha256_hmac_update_64` instead:

```opencl
u32 s0[4] = { hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[0]),
               hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[1]), 0, 0 };
u32 s1[4] = {0}; u32 s2[4] = {0}; u32 s3[4] = {0};
sha256_hmac_update_64(&ctx, s0, s1, s2, s3, 8);
```

Note: `salt_buf` is stored as LE u32 (raw `memcpy`), but `sha256_hmac_update_64` expects BE u32 words, so `hc_swap32_S` is required here.

---

## 17. `m10700` (PDF 1.7 L8) fails with `CL_INVALID_WORK_GROUP_SIZE` on Intel drivers that enforce max 256 threads

**Symptom**: Mode 10700 fails after clearing the kernel cache with either "Kernel m10700-pure.cl build failed" or `clEnqueueNDRangeKernel(): CL_INVALID_WORK_GROUP_SIZE` spam during autotune, speed shown as 0 H/s. Often accompanied by:
```
* Device #1: Runtime returned CL_KERNEL_WORK_GROUP_SIZE=256, but CL_KERNEL_COMPILE_WORK_GROUP_SIZE=392.
```

**Cause**: `module_jit_build_options` in `module_10700.c` computes `FIXED_LOCAL_SIZE` from the device's reported local-memory size (`65536` bytes on UHD 620 → capped to `48*1024` → 392 threads), then embeds it as `reqd_work_group_size(392)` in the compiled kernel via the `KERNEL_FA` macro. Some Intel GPU drivers (e.g. 23.43.027642) report `device_maxworkgroup_size=256` or have a per-kernel effective limit below 392, so the dispatch call is rejected even though compilation succeeded. The bug is that the formula never caps against `device_maxworkgroup_size`.

**Fix** (patch `src/modules/module_10700.c`): after the `kernel_preferred_wgs_multiple` rounding, add a cap:
```c
if (device_param->device_maxworkgroup_size > 0 && fixed_local_size > (u32) device_param->device_maxworkgroup_size)
{
    fixed_local_size = (u32) device_param->device_maxworkgroup_size;
    if (fixed_local_size > device_param->kernel_preferred_wgs_multiple)
        fixed_local_size -= fixed_local_size % device_param->kernel_preferred_wgs_multiple;
}
```
Then `make modules` and `rm -f kernels/m10700-*.kernel`. The patched module auto-selects 252 threads on the UHD 620 (= 256 rounded to wgs_multiple=8).

**Workaround** (without rebuilding): add `-T 256 --force` to your hashcat command.

---

## Quick checklist before shipping a new kernel

1. `rm -f ~/hashcat/kernels/m<MODE>-*.kernel` — always clear cache after editing `.cl`
2. Verify `module_hash_encode` uses `byte_swap_32()` on ALL fields decoded with `hex_to_u32()`
3. Pass scrypt output directly to lowercase `aes128_set_encrypt_key` (no pre-swap)
4. Use `0x00000080` for 0x80 padding at byte-offset 0 within a LE u32 block
5. `SCRYPT_THREADS` constant defined before `#include "scrypt_common.c"`
6. Self-test vector: use `ST_PASS` + `ST_HASH` with a known-good reference implementation output
7. **BLAKE2s / Argon2 VeraCrypt**: remove `hc_swap32_S` in `check_header_*` — both output LE u32, no swap needed
8. **Argon2 `digest_len > 64`**: use custom `argon2_final_N` with Blake2b-long (H') chain — `argon2_final` silently truncates at 64 bytes
9. **`hl32_to_64_S(high, low)`**: first arg = HIGH half (bytes 4–7), second = LOW half (bytes 0–3)
10. **`argon2_common.c`**: `#include` it AFTER `merged_options_t` typedef; `argon2_options_t` must be the first field