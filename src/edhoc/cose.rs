

use alloc::vec::Vec;
use serde_bytes::Bytes;

use super::Result;
use crate::cbor;








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
pub fn serialize_cred_x(x: &[u8], kid : &[u8]) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the COSE_Key.
    // (kty key, kty value, crv key, crv value,
    //  x-coordinate key, x-coordinate value)


    // cred_x is a naked cose key, and thus dressed as a ccs by prefixing (page 15 edhoc9)
    let mut prefix = vec![0xA1, 0x08, 0xA1, 0x01];

    let raw_key = (1,1,2, 2, -1, kid[0], -2, Bytes::new(x));
    // Get the byte representation of it
    let mut bytes = cbor::encode(raw_key)?;
    // This is a CBOR array, but we want a map
    cbor::array_to_map(&mut bytes)?;
    prefix.extend(bytes);
    Ok(prefix)
}


/// Returns the COSE header map for the given `kid`.
pub fn build_id_cred_x(kid: &[u8]) -> Result<Vec<u8>> {
    let map = cbor::build_map_single(kid)?;
    Ok(map)

}

/// Returns the `COSE_Encrypt0` structure used as associated data in the AEAD.
pub fn build_ad(th_i: &[u8]) -> Result<Vec<u8>> {
    // Create array with placeholder
    let mut ad_arr = cbor::encode(("Encrypt0", Bytes::new(b""), 0))?;
    // Remove the placeholder
    ad_arr.pop();
    // Append the transcript hash, which is already CBOR encoded
    ad_arr.extend(th_i);

    Ok(ad_arr)
}




