

use alloc::vec::Vec;
use serde_bytes::Bytes;
use serde::ser::{Serialize, Serializer, SerializeMap};

use super::Result;
use crate::cbor;






/// Returns a CBOR encoded `COSE_KDF_Context`.
///
/// This is used as the info input for the HKDF-Expand step.
///
/// # Arguments
/// * `algorithm_id` - The algorithm name, e.g. "IV-GENERATION" or COSE number
///   e.g. "10" for AES-CCM-16-64-128.
/// * `key_data_length` - The desired key length in bits.
/// * `other` - Typically a transcript hash.
pub fn build_kdf_context(
    algorithm_id: &str,
    key_data_length: usize,
    th: &[u8],
) -> Result<Vec<u8>> {
    // (keyDataLength, protected, placeholder (other))
    let supp_pub_info = (key_data_length, Bytes::new(&[]), 0);
    // It's the same code, but we need different branches  for the type system
    // depending on whether we have a string or number as algorithm_id
    let mut kdf_arr = match algorithm_id.parse::<usize>() {
        // It's a number
        Ok(algorithm_id) => {
            // (AlgorithmID, PartyIInfo, PartyRInfo, SuppPubInfo)
            let cose_kdf_context =
                (algorithm_id, [(); 3], [(); 3], supp_pub_info);
            cbor::encode(cose_kdf_context)?
        }
        // It's a string
        Err(_) => {
            // (AlgorithmID, PartyIInfo, PartyRInfo, SuppPubInfo)
            let cose_kdf_context =
                (algorithm_id, [(); 3], [(); 3], supp_pub_info);
            cbor::encode(cose_kdf_context)?
        }
    };
    // Remove the placeholder item
    kdf_arr.pop();
    // Insert the transcript hash, which is already in its CBOR encoding
    kdf_arr.extend(th);

    Ok(kdf_arr)
}

/// An Octet Key Pair (OKP) `COSE_Key`.
#[derive(Debug, PartialEq)]
pub struct CoseKey {
    kty: usize,
    crv: usize,
    x: Vec<u8>,
}



/// Returns the CBOR encoded `COSE_Key` for the given data.
///
/// This is specific to our use case where we only have Ed25519 public keys,
/// which are Octet Key Pairs (OKP) in COSE and represented as a single
/// x-coordinate.
pub fn serialize_cred_x(x: &[u8], kid : &Vec<u8>) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the COSE_Key.
    // (kty key, kty value, crv key, crv value,
    //  x-coordinate key, x-coordinate value)
    let raw_key = (1,1,2, 2, -1, kid[0], -2, Bytes::new(x));
    // Get the byte representation of it
    let mut bytes = cbor::encode(raw_key)?;
    // This is a CBOR array, but we want a map
    cbor::array_to_map(&mut bytes)?;

    Ok(bytes)
}


/// Returns the COSE header map for the given `kid`.
pub fn build_id_cred_x(kid: &[u8]) -> Result<Vec<u8>> {
    let map = cbor::build_map(kid)?;
    Ok(map)

}

/// Returns the `COSE_Encrypt0` structure used as associated data in the AEAD.
pub fn build_ad(th_i: &[u8]) -> Result<Vec<u8>> {
    // Create array with placeholder
    let mut ad_arr = cbor::encode(("Encrypt0", Bytes::new(&[]), 0))?;
    // Remove the placeholder
    ad_arr.pop();
    // Append the transcript hash, which is already CBOR encoded
    ad_arr.extend(th_i);

    Ok(ad_arr)
}
