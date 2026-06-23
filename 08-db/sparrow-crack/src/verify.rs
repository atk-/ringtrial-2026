use aes::Aes128;
use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};

/// Decrypt the first block of H2 sector 0 using single-key AES-128 XTS and
/// check whether the plaintext starts with the MVStore magic `H:2,`.
///
/// H2's XTS is non-standard: one 16-byte key is used for both the tweak
/// cipher and the data cipher.  See XTS.java in the H2 source.
pub fn check_aes_key(aes_key: &[u8; 16], ct: &[u8; 16]) -> bool {
    let cipher = Aes128::new_from_slice(aes_key).expect("16-byte key is always valid");

    // Sector 0 tweak: AES_ECB_encrypt(key, 16 zero bytes)
    let mut tweak: Block<Aes128> = Block::<Aes128>::default();
    cipher.encrypt_block(&mut tweak);

    // temp = ct XOR tweak
    let mut block = Block::<Aes128>::clone_from_slice(ct);
    for (b, t) in block.iter_mut().zip(tweak.iter()) {
        *b ^= *t;
    }

    // pt = AES_ECB_decrypt(key, temp) XOR tweak
    cipher.decrypt_block(&mut block);
    for (b, t) in block.iter_mut().zip(tweak.iter()) {
        *b ^= *t;
    }

    block[0..10] == *b"H:2,block:"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::parse_hash_line;
    use crate::kdf::derive_aes_key;

    // End-to-end: KDF + XTS oracle for test-sparrow.mv.db, password = "asdfg"
    #[test]
    fn verify_asdfg_end_to_end() {
        let hash = parse_hash_line(
            "$sprw1$853efffddff07a3d$618291f3d09ebabe054d554abc2a9583$f3c67a4ec3b9a4ad004516454e33c82e",
        )
        .unwrap();
        let key = derive_aes_key(b"asdfg", &hash).unwrap();
        assert!(check_aes_key(&key, &hash.ct), "oracle must accept the correct key");
    }

    #[test]
    fn rejects_wrong_password() {
        let hash = parse_hash_line(
            "$sprw1$853efffddff07a3d$618291f3d09ebabe054d554abc2a9583$f3c67a4ec3b9a4ad004516454e33c82e",
        )
        .unwrap();
        let key = derive_aes_key(b"wrongpassword", &hash).unwrap();
        assert!(!check_aes_key(&key, &hash.ct), "oracle must reject wrong key");
    }
}
