/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_twofish.cl)
#include M2S(INCLUDE_PATH/inc_cipher_serpent.cl)
#include M2S(INCLUDE_PATH/inc_cipher_camellia.cl)
#include M2S(INCLUDE_PATH/inc_cipher_kuznyechik.cl)
#endif

#define VC_DATA_LEN (448)
#define VC_SALT_LEN ( 64)

// argon2_options_t MUST be first field — matches C module's merged_options_t
typedef struct merged_options
{
  argon2_options_t argon2_options;

  u32 data_buf[VC_DATA_LEN / 4];
  u32 signature;

} merged_options_t;

typedef struct vc_argon2_tmp
{
  u32 out[48];

} vc_argon2_tmp_t;

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_truecrypt_crc32.cl)
#include M2S(INCLUDE_PATH/inc_truecrypt_xts.cl)
#include M2S(INCLUDE_PATH/inc_veracrypt_xts.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

/**
 * argon2_final_192: Blake2b-long H'(192) for Argon2 192-byte output.
 *
 * hashcat's argon2_final() only handles digest_len <= 64 (fits in one Blake2b
 * output block).  For digest_len = 192 we need the H' chaining construction
 * (RFC 9106 §3.2):
 *
 *   A0   = Blake2b-64 (le32(192) || XOR_last_blocks)  -> take first 32 B
 *   A1   = Blake2b-64 (A0)                            -> take first 32 B
 *   A2   = Blake2b-64 (A1)                            -> take first 32 B
 *   A3   = Blake2b-64 (A2)                            -> take first 32 B
 *   Afin = Blake2b-64 (A3)                            -> take all  64 B
 *   Total: 32*4 + 64 = 192 bytes
 *
 * Each u32 in `out` holds 4 consecutive output bytes in little-endian order.
 */
DECLSPEC void argon2_final_192 (GLOBAL_AS argon2_block_t *blocks, PRIVATE_AS const argon2_options_t *options, PRIVATE_AS u32 *out)
{
  const u32 lane_length = options->lane_length;
  const u32 lanes = options->parallelism;

  blake2b_ctx_t ctx;

  // --- Phase 1: A0 = Blake2b-64(le32(192) || XOR_last_blocks) ---
  //
  // Initialise with 64-byte output (same as blake2b_init but explicit)
  ctx.h[0] = BLAKE2B_IV_00 ^ 0x01010040;
  ctx.h[1] = BLAKE2B_IV_01;
  ctx.h[2] = BLAKE2B_IV_02;
  ctx.h[3] = BLAKE2B_IV_03;
  ctx.h[4] = BLAKE2B_IV_04;
  ctx.h[5] = BLAKE2B_IV_05;
  ctx.h[6] = BLAKE2B_IV_06;
  ctx.h[7] = BLAKE2B_IV_07;

  for (u32 idx = 0; idx < 16; idx++) ctx.m[idx] = 0;

  ctx.len = 0;

  // The XOR of the last blocks forms the 1024-byte input message. Prepend
  // le32(192) via the same sliding-window trick used in argon2_final():
  // each 128-byte chunk is shifted right by 4 bytes and `rem` fills the gap.
  u32 rem = 192; // le32(192) = 0x000000C0 as u32

  for (u32 offset = 0; offset < 128; offset += 16)
  {
    for (u32 l = 0; l < lanes; l++)
    {
      for (u32 idx = 0; idx < 16; idx++)
      {
        ctx.m[idx] ^= blocks[((lane_length - 1) * lanes) + l].values[idx + offset];
      }
    }

    for (u32 idx = 0; idx < 16; idx++)
    {
      const u64 value = ctx.m[idx];
      ctx.m[idx] = hl32_to_64_S (l32_from_64_S (value), rem);
      rem = h32_from_64_S (value);
    }

    ctx.len += 128;
    blake2b_transform (ctx.h, ctx.m, ctx.len, (u64) BLAKE2B_UPDATE);

    for (u32 idx = 0; idx < 16; idx++) ctx.m[idx] = 0;
  }

  ctx.m[0] = hl32_to_64_S (0, rem);
  blake2b_transform (ctx.h, ctx.m, 1028, (u64) BLAKE2B_FINAL);

  // A0 is now in ctx.h[0..7] (64 bytes). Extract all 64 bytes into Ak.
  u32 Ak[16];
  for (u32 i = 0; i < 8; i++)
  {
    Ak[i * 2 + 0] = l32_from_64_S (ctx.h[i]);
    Ak[i * 2 + 1] = h32_from_64_S (ctx.h[i]);
  }

  // Output: first 32 bytes (8 u32) of A0
  for (u32 i = 0; i < 8; i++) out[i] = Ak[i];

  // --- Phase 2: A1..A3, each Blake2b-64(Ak), take first 32 B ---
  for (u32 round = 0; round < 3; round++)
  {
    ctx.h[0] = BLAKE2B_IV_00 ^ 0x01010040;
    ctx.h[1] = BLAKE2B_IV_01;
    ctx.h[2] = BLAKE2B_IV_02;
    ctx.h[3] = BLAKE2B_IV_03;
    ctx.h[4] = BLAKE2B_IV_04;
    ctx.h[5] = BLAKE2B_IV_05;
    ctx.h[6] = BLAKE2B_IV_06;
    ctx.h[7] = BLAKE2B_IV_07;

    // Load Ak (64 bytes) as message; upper 64 bytes of the 128-byte Blake2b
    // block are zero (no more input).
    // hl32_to_64_S(H, L): first arg → bytes 4-7, second arg → bytes 0-3.
    // Ak[i*2] = bytes 0-3 of output u64 i → goes to LOW (second arg).
    // Ak[i*2+1] = bytes 4-7 → goes to HIGH (first arg).
    for (u32 i = 0; i < 8; i++)
      ctx.m[i] = hl32_to_64_S (Ak[i * 2 + 1], Ak[i * 2]);
    for (u32 i = 8; i < 16; i++) ctx.m[i] = 0;

    blake2b_transform (ctx.h, ctx.m, 64, (u64) BLAKE2B_FINAL);

    for (u32 i = 0; i < 8; i++)
    {
      Ak[i * 2 + 0] = l32_from_64_S (ctx.h[i]);
      Ak[i * 2 + 1] = h32_from_64_S (ctx.h[i]);
    }

    // Output: first 32 bytes (8 u32) of this block
    const u32 base = 8 + round * 8;
    for (u32 i = 0; i < 8; i++) out[base + i] = Ak[i];
  }

  // --- Phase 3: Afin = Blake2b-64(A3), output ALL 64 bytes ---
  ctx.h[0] = BLAKE2B_IV_00 ^ 0x01010040;
  ctx.h[1] = BLAKE2B_IV_01;
  ctx.h[2] = BLAKE2B_IV_02;
  ctx.h[3] = BLAKE2B_IV_03;
  ctx.h[4] = BLAKE2B_IV_04;
  ctx.h[5] = BLAKE2B_IV_05;
  ctx.h[6] = BLAKE2B_IV_06;
  ctx.h[7] = BLAKE2B_IV_07;

  for (u32 i = 0; i < 8; i++)
    ctx.m[i] = hl32_to_64_S (Ak[i * 2 + 1], Ak[i * 2]);
  for (u32 i = 8; i < 16; i++) ctx.m[i] = 0;

  blake2b_transform (ctx.h, ctx.m, 64, (u64) BLAKE2B_FINAL);

  // Output: all 64 bytes (16 u32) of Afin
  for (u32 i = 0; i < 8; i++)
  {
    out[32 + i * 2 + 0] = l32_from_64_S (ctx.h[i]);
    out[32 + i * 2 + 1] = h32_from_64_S (ctx.h[i]);
  }
}

// Argon2 output is LE u32 — XTS ciphers also expect LE — no hc_swap32_S
DECLSPEC int check_header_1536 (GLOBAL_AS const merged_options_t *esalt_bufs, GLOBAL_AS const kernel_param_t *kernel_param, GLOBAL_AS u32 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 key1[8];
  u32 key2[8];
  u32 key3[8];
  u32 key4[8];
  u32 key5[8];
  u32 key6[8];

  key1[0] = key[ 0];
  key1[1] = key[ 1];
  key1[2] = key[ 2];
  key1[3] = key[ 3];
  key1[4] = key[ 4];
  key1[5] = key[ 5];
  key1[6] = key[ 6];
  key1[7] = key[ 7];
  key2[0] = key[ 8];
  key2[1] = key[ 9];
  key2[2] = key[10];
  key2[3] = key[11];
  key2[4] = key[12];
  key2[5] = key[13];
  key2[6] = key[14];
  key2[7] = key[15];
  key3[0] = key[16];
  key3[1] = key[17];
  key3[2] = key[18];
  key3[3] = key[19];
  key3[4] = key[20];
  key3[5] = key[21];
  key3[6] = key[22];
  key3[7] = key[23];
  key4[0] = key[24];
  key4[1] = key[25];
  key4[2] = key[26];
  key4[3] = key[27];
  key4[4] = key[28];
  key4[5] = key[29];
  key4[6] = key[30];
  key4[7] = key[31];
  key5[0] = key[32];
  key5[1] = key[33];
  key5[2] = key[34];
  key5[3] = key[35];
  key5[4] = key[36];
  key5[5] = key[37];
  key5[6] = key[38];
  key5[7] = key[39];
  key6[0] = key[40];
  key6[1] = key[41];
  key6[2] = key[42];
  key6[3] = key[43];
  key6[4] = key[44];
  key6[5] = key[45];
  key6[6] = key[46];
  key6[7] = key[47];

  if (verify_header_serpent_twofish_aes         (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, key5, key6, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;
  if (verify_header_kuznyechik_serpent_camellia (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, key5, key6) == 1) return 0;
  if (verify_header_aes_twofish_serpent         (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, key5, key6, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;

  return -1;
}

KERNEL_FQ KERNEL_FA void m34230_init (KERN_ATTR_TMPS_ESALT (vc_argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  argon2_init_gg (&pws[gid], &salt_bufs[SALT_POS_HOST], &argon2_options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m34230_loop (KERN_ATTR_TMPS_ESALT (vc_argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #ifdef ARGON2_PARALLELISM
  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  #else
  LOCAL_VK u64 shuffle_bufs[32][32];
  #endif

  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  SYNC_THREADS ();

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS void *V;

  switch (bm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST_BID].argon2_options;

  #ifdef IS_APPLE
  // doesn't work on Apple
  #else
  #ifdef ARGON2_PARALLELISM
  argon2_options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < argon2_options.parallelism; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_block, &argon2_options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
    }

    SYNC_THREADS ();

    pos.slice++;

    if (pos.slice == ARGON2_SYNC_POINTS)
    {
      pos.slice = 0;
      pos.pass++;
    }
  }
}

KERNEL_FQ KERNEL_FA void m34230_comp (KERN_ATTR_TMPS_ESALT (vc_argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

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

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  u32 out[48];

  argon2_final_192 (argon2_block, &argon2_options, out);

  // Argon2 output is LE u32 — pass directly to check_header_1536 (no swap)

  if (check_header_1536 (esalt_bufs, kernel_param, out, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
