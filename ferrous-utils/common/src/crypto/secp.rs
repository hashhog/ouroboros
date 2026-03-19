// Optimized secp256k1 signature verification
//
// Uses the libsecp256k1 library (via rust-secp256k1 crate) with:
// - Pre-computed endomorphism tables for faster scalar multiplication
// - Global context for amortized setup cost
// - Batch verification for Schnorr signatures (Taproot)
//
// Reference: Bitcoin Core's libsecp256k1

use secp256k1::{
    ecdsa::Signature as EcdsaSignature, schnorr::Signature as SchnorrSignature, Error, Message,
    PublicKey, Secp256k1, XOnlyPublicKey,
};
use std::sync::OnceLock;

/// Global secp256k1 verification context (initialized once)
/// This amortizes the cost of computing pre-computed tables across all verifications
static SECP_CTX: OnceLock<Secp256k1<secp256k1::All>> = OnceLock::new();

/// Get the global secp256k1 context
fn get_context() -> &'static Secp256k1<secp256k1::All> {
    SECP_CTX.get_or_init(Secp256k1::new)
}

/// Verify an ECDSA signature (compact 64-byte format)
///
/// # Arguments
/// * `sig` - 64-byte compact signature (r || s)
/// * `pubkey` - SEC1 encoded public key (33 or 65 bytes)
/// * `msg_hash` - 32-byte message hash
///
/// # Returns
/// * `Ok(true)` if valid
/// * `Ok(false)` if invalid signature
/// * `Err` if malformed input
pub fn verify_ecdsa_compact(sig: &[u8], pubkey: &[u8], msg_hash: &[u8]) -> Result<bool, Error> {
    let ctx = get_context();
    let pubkey = PublicKey::from_slice(pubkey)?;
    let signature = EcdsaSignature::from_compact(sig)?;

    if msg_hash.len() != 32 {
        return Err(Error::InvalidMessage);
    }
    let msg_array: [u8; 32] = msg_hash.try_into().map_err(|_| Error::InvalidMessage)?;
    let message = Message::from_digest(msg_array);

    match ctx.verify_ecdsa(message, &signature, &pubkey) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify an ECDSA signature (DER-encoded, as used in Bitcoin scripts)
///
/// # Arguments
/// * `der_sig` - DER-encoded signature (without sighash byte)
/// * `pubkey` - SEC1 encoded public key (33 or 65 bytes)
/// * `msg_hash` - 32-byte message hash (double-SHA256 of signed data)
///
/// # Returns
/// * `Ok(true)` if valid
/// * `Ok(false)` if invalid signature
/// * `Err` if malformed input
pub fn verify_ecdsa_der(der_sig: &[u8], pubkey: &[u8], msg_hash: &[u8]) -> Result<bool, Error> {
    let ctx = get_context();
    let pubkey = PublicKey::from_slice(pubkey)?;
    let signature = EcdsaSignature::from_der(der_sig)?;

    if msg_hash.len() != 32 {
        return Err(Error::InvalidMessage);
    }
    let msg_array: [u8; 32] = msg_hash.try_into().map_err(|_| Error::InvalidMessage)?;
    let message = Message::from_digest(msg_array);

    match ctx.verify_ecdsa(message, &signature, &pubkey) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a Schnorr signature (BIP340, used in Taproot)
///
/// # Arguments
/// * `sig` - 64-byte Schnorr signature
/// * `pubkey` - 32-byte x-only public key
/// * `msg_hash` - 32-byte message hash
///
/// # Returns
/// * `Ok(true)` if valid
/// * `Ok(false)` if invalid signature
/// * `Err` if malformed input
pub fn verify_schnorr(sig: &[u8], pubkey: &[u8], msg_hash: &[u8]) -> Result<bool, Error> {
    let ctx = get_context();

    if sig.len() != 64 {
        return Err(Error::InvalidSignature);
    }
    let sig_array: [u8; 64] = sig.try_into().map_err(|_| Error::InvalidSignature)?;
    let signature = SchnorrSignature::from_byte_array(sig_array);

    if pubkey.len() != 32 {
        return Err(Error::InvalidPublicKey);
    }
    let pk_array: [u8; 32] = pubkey.try_into().map_err(|_| Error::InvalidPublicKey)?;
    let xonly_pubkey = XOnlyPublicKey::from_byte_array(pk_array)?;

    if msg_hash.len() != 32 {
        return Err(Error::InvalidMessage);
    }

    // verify_schnorr expects a raw message byte slice, not a Message struct
    match ctx.verify_schnorr(&signature, msg_hash, &xonly_pubkey) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Item for batch Schnorr verification
pub struct SchnorrVerifyItem<'a> {
    /// 64-byte signature
    pub sig: &'a [u8],
    /// 32-byte x-only public key
    pub pubkey: &'a [u8],
    /// 32-byte message hash
    pub msg_hash: &'a [u8],
}

/// Batch verify multiple Schnorr signatures
///
/// Batch verification is more efficient than verifying signatures individually
/// when verifying multiple signatures from a block. Uses the linearity of Schnorr
/// signatures to amortize scalar multiplication costs.
///
/// Note: The rust-secp256k1 crate doesn't expose batch verification directly,
/// so this implementation falls back to sequential verification.
/// For true batch verification, we would need to use libsecp256k1-zkp or
/// implement the batch verification algorithm manually.
///
/// # Arguments
/// * `items` - Slice of signature/pubkey/message tuples to verify
///
/// # Returns
/// * `Ok(true)` if ALL signatures are valid
/// * `Ok(false)` if ANY signature is invalid
/// * `Err` if any input is malformed
pub fn batch_verify_schnorr(items: &[SchnorrVerifyItem<'_>]) -> Result<bool, Error> {
    // TODO: True batch verification would use the following approach:
    // 1. Generate random scalars a_1, a_2, ..., a_n
    // 2. Check: sum(a_i * s_i * G) = sum(a_i * R_i) + sum(a_i * e_i * P_i)
    // This is ~2x faster than individual verification for large batches.
    //
    // For now, fall back to sequential verification since rust-secp256k1
    // doesn't expose the batch verification API.

    for item in items {
        match verify_schnorr(item.sig, item.pubkey, item.msg_hash)? {
            true => continue,
            false => return Ok(false),
        }
    }
    Ok(true)
}

/// Item for batch ECDSA verification
pub struct EcdsaVerifyItem<'a> {
    /// DER-encoded signature (without sighash byte)
    pub sig: &'a [u8],
    /// SEC1-encoded public key (33 or 65 bytes)
    pub pubkey: &'a [u8],
    /// 32-byte message hash
    pub msg_hash: &'a [u8],
}

/// Batch verify multiple ECDSA signatures
///
/// Unlike Schnorr, ECDSA doesn't have an efficient batch verification algorithm.
/// This function verifies signatures sequentially but benefits from the
/// pre-computed global context.
///
/// # Arguments
/// * `items` - Slice of signature/pubkey/message tuples to verify
///
/// # Returns
/// * `Ok(true)` if ALL signatures are valid
/// * `Ok(false)` if ANY signature is invalid
/// * `Err` if any input is malformed
pub fn batch_verify_ecdsa(items: &[EcdsaVerifyItem<'_>]) -> Result<bool, Error> {
    for item in items {
        match verify_ecdsa_der(item.sig, item.pubkey, item.msg_hash)? {
            true => continue,
            false => return Ok(false),
        }
    }
    Ok(true)
}

/// Parse a SEC1-encoded public key and return canonical compressed form
///
/// # Arguments
/// * `pubkey` - SEC1 encoded public key (33 or 65 bytes)
///
/// # Returns
/// * 33-byte compressed public key
pub fn compress_pubkey(pubkey: &[u8]) -> Result<[u8; 33], Error> {
    let pk = PublicKey::from_slice(pubkey)?;
    Ok(pk.serialize())
}

/// Parse a SEC1-encoded public key and return uncompressed form
///
/// # Arguments
/// * `pubkey` - SEC1 encoded public key (33 or 65 bytes)
///
/// # Returns
/// * 65-byte uncompressed public key
pub fn uncompress_pubkey(pubkey: &[u8]) -> Result<[u8; 65], Error> {
    let pk = PublicKey::from_slice(pubkey)?;
    Ok(pk.serialize_uncompressed())
}

/// Extract x-only public key from full public key (for Taproot)
///
/// # Arguments
/// * `pubkey` - SEC1 encoded public key (33 or 65 bytes)
///
/// # Returns
/// * 32-byte x-only public key
pub fn to_xonly_pubkey(pubkey: &[u8]) -> Result<[u8; 32], Error> {
    let pk = PublicKey::from_slice(pubkey)?;
    let (xonly, _parity) = pk.x_only_public_key();
    Ok(xonly.serialize())
}

/// Check if a public key is valid
pub fn is_valid_pubkey(pubkey: &[u8]) -> bool {
    PublicKey::from_slice(pubkey).is_ok()
}

/// Check if an x-only public key is valid
pub fn is_valid_xonly_pubkey(pubkey: &[u8]) -> bool {
    if pubkey.len() != 32 {
        return false;
    }
    let pk_array: [u8; 32] = match pubkey.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    XOnlyPublicKey::from_byte_array(pk_array).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_verification() {
        // Test vector from Bitcoin Core
        // This is a simplified test - real tests would use actual Bitcoin signatures

        // Invalid signature should return Ok(false), not error
        let sig = vec![0u8; 64];
        let pubkey = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap(); // Generator point
        let msg = [0u8; 32];

        let result = verify_ecdsa_compact(&sig, &pubkey, &msg);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Invalid signature
    }

    #[test]
    fn test_schnorr_verification() {
        // BIP340 test vector #0
        let seckey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();
        let pubkey =
            hex::decode("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
                .unwrap();
        let msg = hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let sig = hex::decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
            .unwrap();

        let result = verify_schnorr(&sig, &pubkey, &msg);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify with wrong message fails
        let wrong_msg = [1u8; 32];
        let result2 = verify_schnorr(&sig, &pubkey, &wrong_msg);
        assert!(result2.is_ok());
        assert!(!result2.unwrap());

        // Suppress unused variable warning
        let _ = seckey;
    }

    #[test]
    fn test_batch_schnorr() {
        // BIP340 test vector #0
        let pubkey =
            hex::decode("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
                .unwrap();
        let msg = hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let sig = hex::decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
            .unwrap();

        let items = vec![
            SchnorrVerifyItem {
                sig: &sig,
                pubkey: &pubkey,
                msg_hash: &msg,
            },
            SchnorrVerifyItem {
                sig: &sig,
                pubkey: &pubkey,
                msg_hash: &msg,
            },
        ];

        let result = batch_verify_schnorr(&items);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_pubkey_compression() {
        // Generator point G
        let compressed =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();

        let uncompressed = uncompress_pubkey(&compressed).unwrap();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);

        let recompressed = compress_pubkey(&uncompressed).unwrap();
        assert_eq!(recompressed.as_slice(), compressed.as_slice());
    }

    #[test]
    fn test_xonly_pubkey() {
        let compressed =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();

        let xonly = to_xonly_pubkey(&compressed).unwrap();
        assert_eq!(xonly.len(), 32);
        // x-coordinate without prefix
        assert_eq!(
            hex::encode(xonly),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_pubkey_validation() {
        // Valid compressed pubkey
        let valid =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        assert!(is_valid_pubkey(&valid));

        // Invalid pubkey (wrong prefix)
        let invalid =
            hex::decode("0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        assert!(!is_valid_pubkey(&invalid));

        // Invalid pubkey (too short)
        let short = vec![0x02; 32];
        assert!(!is_valid_pubkey(&short));
    }
}
