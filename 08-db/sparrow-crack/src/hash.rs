/// Parsed $sprw1$ hash — all fields as raw bytes.
#[derive(Clone, Debug)]
pub struct SprwHash {
    /// 8-byte H2 internal salt (file offset 10)
    pub h2_salt: [u8; 8],
    /// 16-byte Argon2id salt (file offset 24)
    pub argon2_salt: [u8; 16],
    /// First 16 bytes of encrypted sector 0 (the XTS oracle ciphertext)
    pub ct: [u8; 16],
}

/// Parse a `$sprw1$<h2_salt>$<argon2_salt>$<ct>` line.
///
/// Returns an error string on any format or decode problem.
pub fn parse_hash_line(line: &str) -> Result<SprwHash, String> {
    let s = line.trim();

    if s.starts_with("$h2$") {
        return Err(
            "Legacy $h2$ format — re-extract with h2db2john.py to get $sprw1$ format \
             (the Argon2 salt is required for Sparrow cracking)"
                .to_string(),
        );
    }

    if !s.starts_with("$sprw1$") {
        return Err(format!("Unknown hash format (expected $sprw1$...): {s}"));
    }

    // expected: $sprw1$ <h2_salt_hex(16)> $ <argon2_salt_hex(32)> $ <ct_hex(32)>
    // split on '$' gives: ["", "sprw1", h2, argon2, ct]
    let parts: Vec<&str> = s.split('$').collect();
    if parts.len() != 5 {
        return Err(format!(
            "Expected 5 $-separated fields in $sprw1$ hash, got {}",
            parts.len()
        ));
    }

    let h2_hex     = parts[2];
    let argon2_hex = parts[3];
    let ct_hex     = parts[4];

    let h2_bytes = decode_hex_field("h2_salt", h2_hex, 16)?;
    let argon2_bytes = decode_hex_field("argon2_salt", argon2_hex, 32)?;
    let ct_bytes = decode_hex_field("ct", ct_hex, 32)?;

    Ok(SprwHash {
        h2_salt:     h2_bytes.try_into().unwrap(),
        argon2_salt: argon2_bytes.try_into().unwrap(),
        ct:          ct_bytes.try_into().unwrap(),
    })
}

fn decode_hex_field(name: &str, hex: &str, expected_chars: usize) -> Result<Vec<u8>, String> {
    if hex.len() != expected_chars {
        return Err(format!(
            "Field '{name}': expected {expected_chars} hex chars, got {}",
            hex.len()
        ));
    }
    hex::decode(hex).map_err(|e| format!("Field '{name}': hex decode error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_hash() {
        // my_crypto.mv.db
        let line = "$sprw1$9b68ff93ef35c261$5f136c0164452b966e2ccf2aa4b10f0f$fb62a413ea22ab5a333fd5ed400910c8";
        let h = parse_hash_line(line).unwrap();
        assert_eq!(h.h2_salt,     hex::decode("9b68ff93ef35c261").unwrap().as_slice());
        assert_eq!(h.argon2_salt, hex::decode("5f136c0164452b966e2ccf2aa4b10f0f").unwrap().as_slice());
        assert_eq!(h.ct,          hex::decode("fb62a413ea22ab5a333fd5ed400910c8").unwrap().as_slice());
    }

    #[test]
    fn rejects_legacy_h2() {
        let e = parse_hash_line("$h2$10$9b68ff93ef35c261$fb62a413ea22ab5a333fd5ed400910c8")
            .unwrap_err();
        assert!(e.contains("Legacy"), "{e}");
    }

    #[test]
    fn rejects_unknown_format() {
        let e = parse_hash_line("notahash").unwrap_err();
        assert!(e.contains("Unknown"), "{e}");
    }

    #[test]
    fn trims_whitespace_and_newlines() {
        let line = "  $sprw1$9b68ff93ef35c261$5f136c0164452b966e2ccf2aa4b10f0f$fb62a413ea22ab5a333fd5ed400910c8  \n";
        assert!(parse_hash_line(line).is_ok());
    }
}
