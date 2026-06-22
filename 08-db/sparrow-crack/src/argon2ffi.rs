// FFI binding to system libargon2 (phc-winner-argon2).
// libargon2 runs p=4 lanes via pthreads in parallel, giving ~4–8× lower
// latency per call vs the RustCrypto pure-Rust sequential implementation.
extern "C" {
    fn argon2id_hash_raw(
        t_cost:      u32,
        m_cost:      u32,
        parallelism: u32,
        pwd:         *const u8,
        pwdlen:      usize,
        salt:        *const u8,
        saltlen:     usize,
        hash:        *mut u8,
        hashlen:     usize,
    ) -> i32;
}

/// Run Argon2id with Sparrow Wallet's fixed parameters.
///
/// Parameters are hardcoded to match `SPRW1_PARAMETERS` in Sparrow:
///   t=10, m=262144 KiB (256 MB), p=4, output=32 bytes
pub fn argon2id_sparrow(password: &[u8], salt: &[u8], out: &mut [u8; 32]) -> Result<(), String> {
    let rc = unsafe {
        argon2id_hash_raw(
            10,
            262_144,
            4,
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            out.as_mut_ptr(),
            32,
        )
    };
    match rc {
        0 => Ok(()),
        e => Err(format!("libargon2 returned error code {e}")),
    }
}
