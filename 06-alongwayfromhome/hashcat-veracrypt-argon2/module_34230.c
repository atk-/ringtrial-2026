/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "argon2_common.h"

#define ARGON2_VERSION_13   0x13
#define ARGON2_TYPE_ID      2

// VeraCrypt fork: Argon2id, p=1 hardcoded, default PIM=12
// m = 64 + (PIM-1)*32 MiB; t = 3 + floor((PIM-1)/3)
// PIM=12: m = 64 + 11*32 = 416 MiB; t = 3 + floor(11/3) = 6
#define ARGON2_M_COST   425984  // 416 MiB in KiB (PIM=12)
#define ARGON2_T_COST   6       // (PIM=12)
#define ARGON2_P_COST   1       // hardcoded in patched VeraCrypt
#define ARGON2_OUTLEN   192     // 6 x 32 bytes for XTS-1536

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_32;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "VeraCrypt fork Argon2id + XTS 1536 bit";
static const u64   KERN_TYPE      = 34230;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_DIMY_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "salasana";
static const char *ST_HASH        = "$veracrypt$5b4fdbca1d5d78c2894384e2f0405df376591c9e6417f182dfe195960c4ebdbcd317f36fab871d3c92990f34ef125338d879ac6201b94b4c94948d7dd5f0480c$497240e119bd22ecf229fc7fa9d0474620f75bb9e4569423d9a85e68d9215c7a7f42de8ebb8f7688aeb61c383e1f1d9ffd6cd0feaf7e030b2fc63d7879c65f337c18ab955b298de2882ebfa3eb79f8227393c2c07c79d18ff266af69b02bec9666cc625c29587c6920f60df73464afa6a59db9173c801bc27711fe20afd41906685dabc99bb0f48a77e5143606ccc5254a91cdf795e17fdf72e8c260acf8db0dd45b8df1bee0669042540c3a246c787a010266299cdc2c1b84c537c04aae74efa5f8418044e5c6f181f9f22f648175e8029634cddda76edf9e97446b4cb84d37380247c9d8f56296db4cdd3bd9ca417eb3aada59bc1d3cdd9e5831c17809715c566959e5efa6c0034361fe940f11488c40c529ecd8e571e89f6664966f856fc4a5c4d3aeb74875895cc9121c32b5bae0865eb78dc67310f8ae8aa48765735a41485d1679c2b27c8dcda65b96c45fa5811bf93e50f4ce982a48d2dcea2f632f573343e72a8eae6e5e74f725fe5c4b23462e825ef86a7f27434cea1f30a9e1cb4615336546e778b6a4d0806b37d4852d5717aa82925bf1317845639cbafe6d5f45932a7a44b7a6e881758e01c55333538d4154a0ce9e821f273fcc959fca658658";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

#define VC_SALT_LEN     (             64)
#define VC_SALT_HEX_LEN (VC_SALT_LEN * 2)

#define VC_DATA_LEN     (            448)
#define VC_DATA_HEX_LEN (VC_DATA_LEN * 2)

typedef struct vc_argon2_tmp
{
  u32 out[48]; // 192-byte Argon2 output (placeholder; not used between kernels)

} vc_argon2_tmp_t;

// argon2_options_t MUST be first field — argon2_common.c casts esalt to merged_options_t *
typedef struct merged_options
{
  argon2_options_t argon2_options;

  u32 data_buf[VC_DATA_LEN / 4];
  u32 signature;

} merged_options_t;

#include "argon2_common.c"

static const float MIN_SUFFICIENT_ENTROPY_FILE = 7.0f;
static const char *SIGNATURE_VERACRYPT         = "$veracrypt$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (merged_options_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (vc_argon2_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 128;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  merged_options_t *merged_options = (merged_options_t *) esalt_buf;

  argon2_options_t *argon2_options = &merged_options->argon2_options;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_VERACRYPT;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = VC_SALT_HEX_LEN;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len[2]     = VC_DATA_HEX_LEN;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];

  salt->salt_len = hex_decode (salt_pos, VC_SALT_HEX_LEN, (u8 *) salt->salt_buf);

  // argon2 loop iterations: t_cost * ARGON2_SYNC_POINTS (no -1)

  salt->salt_iter = ARGON2_T_COST * ARGON2_SYNC_POINTS;

  // argon2 parallelism (Y dimension of kernel dispatch)

  salt->salt_dimy = ARGON2_P_COST;

  // data

  const u8 *data_pos = token.buf[2];

  hex_decode (data_pos, VC_DATA_HEX_LEN, (u8 *) merged_options->data_buf);

  // entropy check

  const float entropy = get_entropy ((const u8 *) merged_options->data_buf, VC_DATA_LEN);

  if (entropy < MIN_SUFFICIENT_ENTROPY_FILE) return (PARSER_INSUFFICIENT_ENTROPY);

  // signature

  merged_options->signature = 0x41524556; // "VERA"

  // argon2 options (all fixed for this VeraCrypt fork)

  argon2_options->type               = ARGON2_TYPE_ID;
  argon2_options->version            = ARGON2_VERSION_13;
  argon2_options->iterations         = ARGON2_T_COST;
  argon2_options->parallelism        = ARGON2_P_COST;
  argon2_options->memory_usage_in_kib = ARGON2_M_COST;
  argon2_options->segment_length     = MAX (2, (ARGON2_M_COST / (ARGON2_SYNC_POINTS * ARGON2_P_COST)));
  argon2_options->lane_length        = argon2_options->segment_length * ARGON2_SYNC_POINTS;
  argon2_options->memory_block_count = argon2_options->lane_length * ARGON2_P_COST;
  argon2_options->digest_len         = ARGON2_OUTLEN;

  // fake digest (first 112 bytes of encrypted header for dedup purposes)

  memcpy (digest, merged_options->data_buf, VC_DATA_LEN / 4);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const merged_options_t *merged_options = (const merged_options_t *) esalt_buf;

  char salt_buf[VC_SALT_HEX_LEN + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, VC_SALT_LEN, (u8 *) salt_buf);

  char data_buf[VC_DATA_HEX_LEN + 1] = { 0 };

  hex_encode ((const u8 *) merged_options->data_buf, VC_DATA_LEN, (u8 *) data_buf);

  int line_len = snprintf (line_buf, line_size, "%s%s$%s",
    SIGNATURE_VERACRYPT,
    salt_buf,
    data_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = argon2_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = argon2_module_extra_tuningdb_block;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = argon2_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
