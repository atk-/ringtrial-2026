/**
 * Author......: Aleksi Keurulainen
 * License.....: MIT
 *
 * Mode 35900 — H2 MVStore encrypted database (.mv.db)
 *
 * KDF : PBKDF2-HMAC-SHA256, 10 iterations, dkLen=16, password in UTF-16BE
 * Cipher: single-key AES-128-XTS (one key for both data and tweak AES)
 * Verify: decrypt first 16-byte block of sector 0; check bytes[0..3] == "H:2,"
 *
 * Pitfall notes (HASHCAT_ISSUES.md):
 *  #2  : hex_to_u32 stores LE u32; encode path needs byte_swap_32
 *  #3  : SHA-256 output is BE u32; swap before aes128_set_*_key (lowercase)
 *  #16 : sha256_hmac_update_global_swap over-reads 64 bytes; use zero-padded
 *        private array + sha256_hmac_update_64 for the 8-byte salt
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct h2_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} h2_tmp_t;

typedef struct h2
{
  u32 ct[4];  // first 16 bytes of encrypted sector 0

} h2_t;

// hmac_sha256_run_V: perform one PBKDF2 inner+outer SHA-256 pass (vectorised)
DECLSPEC void hmac_sha256_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

// ---------------------------------------------------------------------------
// _init: expand password to UTF-16BE, run PBKDF2 iteration 1
// ---------------------------------------------------------------------------

KERNEL_FQ KERNEL_FA void m35900_init (KERN_ATTR_TMPS_ESALT (h2_tmp_t, h2_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // ------------------------------------------------------------------
  // Expand password to UTF-16BE in private memory as LE u32 words.
  //
  // For each input byte b at byte-position i (0-indexed):
  //   UTF-16BE output bytes: [0x00, b] at positions [2i, 2i+1]
  //
  // Packed as LE u32 (LSByte first in memory):
  //   For input word w[k] with bytes b0..b3 (b0=LSByte):
  //     ew[2k]   = (b1 << 24) | (b0 << 8)
  //     ew[2k+1] = (b3 << 24) | (b2 << 8)
  //
  // sha256_hmac_init_swap applies hc_swap32_S to each word, converting
  // LE u32 to the BE u32 format that SHA-256 expects natively.
  // ------------------------------------------------------------------

  const u32 pw_len  = pws[gid].pw_len;
  const u32 pw_nw   = (pw_len + 3) / 4;  // number of full/partial input words
  const u32 utf_len = pw_len * 2;         // UTF-16BE byte length

  // ew[] must cover ≥ 16 words (sha256_hmac_init_swap reads w[0..15] when
  // utf_len ≤ 64) and ≥ utf_len/4 words for longer passwords.
  u32 ew[64];

  for (u32 i = 0; i < 64; i++) ew[i] = 0;

  for (u32 k = 0; k < pw_nw; k++)
  {
    const u32 w  = pws[gid].i[k];
    const u32 b0 = (w >>  0) & 0xFF;
    const u32 b1 = (w >>  8) & 0xFF;
    const u32 b2 = (w >> 16) & 0xFF;
    const u32 b3 = (w >> 24) & 0xFF;
    ew[2 * k    ] = (b1 << 24) | (b0 << 8);
    ew[2 * k + 1] = (b3 << 24) | (b2 << 8);
  }

  // ------------------------------------------------------------------
  // HMAC-SHA256 init with UTF-16BE password
  // sha256_hmac_init_swap takes LE u32 private memory, swaps to BE u32
  // ------------------------------------------------------------------

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, ew, utf_len);

  // Save ipad/opad — reused by _loop for subsequent PBKDF2 iterations
  tmps[gid].ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha256_hmac_ctx.opad.h[7];

  // ------------------------------------------------------------------
  // Feed salt (8 bytes) using zero-padded private array to avoid
  // the sha256_hmac_update_global_swap 64-byte over-read (Issue #16).
  //
  // salt_bufs stores salt as LE u32 (from raw memcpy in module_hash_decode).
  // sha256_hmac_update_64 expects BE u32, so we swap each word.
  // ------------------------------------------------------------------

  u32 s0[4];
  u32 s1[4];
  u32 s2[4];
  u32 s3[4];

  s0[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[0]);
  s0[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[1]);
  s0[2] = 0;
  s0[3] = 0;
  s1[0] = 0; s1[1] = 0; s1[2] = 0; s1[3] = 0;
  s2[0] = 0; s2[1] = 0; s2[2] = 0; s2[3] = 0;
  s3[0] = 0; s3[1] = 0; s3[2] = 0; s3[3] = 0;

  sha256_hmac_update_64 (&sha256_hmac_ctx, s0, s1, s2, s3, 8);

  // ------------------------------------------------------------------
  // PBKDF2 block 1: append counter = 1 (big-endian u32), then finalise
  // ------------------------------------------------------------------

  sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

  u32 c0[4];
  u32 c1[4];
  u32 c2[4];
  u32 c3[4];

  c0[0] = 1;  // PBKDF2 block counter = 1 as BE u32
  c0[1] = 0;
  c0[2] = 0;
  c0[3] = 0;
  c1[0] = 0; c1[1] = 0; c1[2] = 0; c1[3] = 0;
  c2[0] = 0; c2[1] = 0; c2[2] = 0; c2[3] = 0;
  c3[0] = 0; c3[1] = 0; c3[2] = 0; c3[3] = 0;

  sha256_hmac_update_64 (&sha256_hmac_ctx2, c0, c1, c2, c3, 4);
  sha256_hmac_final (&sha256_hmac_ctx2);

  // Store U1 result (BE u32 from SHA-256 output)
  tmps[gid].dgst[0] = sha256_hmac_ctx2.opad.h[0];
  tmps[gid].dgst[1] = sha256_hmac_ctx2.opad.h[1];
  tmps[gid].dgst[2] = sha256_hmac_ctx2.opad.h[2];
  tmps[gid].dgst[3] = sha256_hmac_ctx2.opad.h[3];
  tmps[gid].dgst[4] = sha256_hmac_ctx2.opad.h[4];
  tmps[gid].dgst[5] = sha256_hmac_ctx2.opad.h[5];
  tmps[gid].dgst[6] = sha256_hmac_ctx2.opad.h[6];
  tmps[gid].dgst[7] = sha256_hmac_ctx2.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}

// ---------------------------------------------------------------------------
// _loop: PBKDF2 iterations 2..N (SIMD vectorised)
// ---------------------------------------------------------------------------

KERNEL_FQ KERNEL_FA void m35900_loop (KERN_ATTR_TMPS_ESALT (h2_tmp_t, h2_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);
  ipad[5] = packv (tmps, ipad, gid, 5);
  ipad[6] = packv (tmps, ipad, gid, 6);
  ipad[7] = packv (tmps, ipad, gid, 7);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);
  opad[5] = packv (tmps, opad, gid, 5);
  opad[6] = packv (tmps, opad, gid, 6);
  opad[7] = packv (tmps, opad, gid, 7);

  // One PRF block (8 u32 words = 32 bytes; we only need first 16 bytes as key)
  for (u32 i = 0; i < 8; i += 8)
  {
    u32x dgst[8];
    u32x out[8];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);
    dgst[5] = packv (tmps, dgst, gid, i + 5);
    dgst[6] = packv (tmps, dgst, gid, i + 6);
    dgst[7] = packv (tmps, dgst, gid, i + 7);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);
    out[5] = packv (tmps, out, gid, i + 5);
    out[6] = packv (tmps, out, gid, i + 6);
    out[7] = packv (tmps, out, gid, i + 7);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);
    unpackv (tmps, dgst, gid, i + 5, dgst[5]);
    unpackv (tmps, dgst, gid, i + 6, dgst[6]);
    unpackv (tmps, dgst, gid, i + 7, dgst[7]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
    unpackv (tmps, out, gid, i + 5, out[5]);
    unpackv (tmps, out, gid, i + 6, out[6]);
    unpackv (tmps, out, gid, i + 7, out[7]);
  }
}

// ---------------------------------------------------------------------------
// _comp: derive AES-128 key, H2 single-key XTS decrypt, verify "H:2,"
// ---------------------------------------------------------------------------

KERNEL_FQ KERNEL_FA void m35900_comp (KERN_ATTR_TMPS_ESALT (h2_tmp_t, h2_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id  (0);
  const u64 lsz = get_local_size (0);

  // Load AES lookup tables into local (shared) memory
#ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

#else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

#endif

  if (gid >= GID_CNT) return;

  // ------------------------------------------------------------------
  // Derive 16-byte AES-128 key from PBKDF2 output (first 4 words).
  //
  // tmps[gid].out[] holds BE u32 from SHA-256. aes128_set_*_key
  // (lowercase) expects LE u32 (Issue #3), so apply hc_swap32_S.
  // ------------------------------------------------------------------

  u32 ukey[4];

  ukey[0] = hc_swap32_S (tmps[gid].out[0]);
  ukey[1] = hc_swap32_S (tmps[gid].out[1]);
  ukey[2] = hc_swap32_S (tmps[gid].out[2]);
  ukey[3] = hc_swap32_S (tmps[gid].out[3]);

  // ------------------------------------------------------------------
  // Set up AES key schedules.
  // H2 uses the SAME key for both tweak AES and data AES (non-standard).
  // ------------------------------------------------------------------

  u32 ks_enc[44];
  u32 ks_dec[44];

  aes128_set_encrypt_key (ks_enc, ukey, s_te0, s_te1, s_te2, s_te3);
  aes128_set_decrypt_key (ks_dec, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  // ------------------------------------------------------------------
  // Compute XTS tweak for sector 0, block 0.
  //
  // H2 XTS.initTweak(id=0): sector_id 0 encoded as 16 LE zero bytes,
  // then AES_encrypt with the (tweak) key.
  // In hashcat LE u32: sector 0 = {0, 0, 0, 0} (same in any byte order).
  // ------------------------------------------------------------------

  u32 T[4] = { 0, 0, 0, 0 };

  aes128_encrypt (ks_enc, T, T, s_te0, s_te1, s_te2, s_te3, s_te4);

  // ------------------------------------------------------------------
  // Decrypt block 0 of sector 0.
  //
  // H2 XTS.decrypt: when i==0, updateTweak is NOT called before the
  // first block — the initial tweak is used directly.
  //
  // pt = AES_decrypt(key, ct XOR T) XOR T
  //
  // esalt->ct[] was stored via hex_to_u32 (LE u32, Issue #2).
  // aes128_decrypt input/output are also LE u32 (Issue #4 analogue).
  // ------------------------------------------------------------------

  u32 ct[4];

  ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[0] ^ T[0];
  ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[1] ^ T[1];
  ct[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[2] ^ T[2];
  ct[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[3] ^ T[3];

  aes128_decrypt (ks_dec, ct, ct, s_td0, s_td1, s_td2, s_td3, s_td4);

  ct[0] ^= T[0];
  ct[1] ^= T[1];
  ct[2] ^= T[2];
  ct[3] ^= T[3];

  // ------------------------------------------------------------------
  // Verify oracle: MVStore header is always "H:2,block:..." because
  // DataUtils.appendMap sorts keys lexicographically and 'H' (0x48)
  // precedes all lowercase keys.
  //
  // ct[0] = "H:2," = LE u32 0x2c323a48
  // ct[1] = "bloc" = LE u32 0x636f6c62
  //
  // 64-bit check eliminates false positives at any practical wordlist size.
  // ------------------------------------------------------------------

  if (ct[0] == 0x2c323a48u && ct[1] == 0x636f6c62u)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
