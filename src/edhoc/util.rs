use aes::Aes128;
use x25519_dalek_ng::{PublicKey};

use alloc::{string::String, vec::Vec};
use ccm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    consts::{U13, U8},
    Ccm,
};
use digest::{FixedOutput, Input};
use hkdf::Hkdf;
use serde_bytes::{ByteBuf, Bytes};
use sha2::Sha256;
use super::{cose, error::Error, Result};
use crate::cbor;


// length in bits
pub const CCM_KEY_LEN: usize = 128;
pub const CCM_NONCE_LEN: usize = 104;
pub const SALT_LENGTH : usize = 64;
pub const EDHOC_MAC :usize = 64;
pub const HASHFUNC_OUTPUT_LEN_BITS: usize = 256;
pub const CONNECTION_IDENTIFIER_LENGTH: usize = 8;



/// EDHOC `message_1`.
#[derive(Debug, PartialEq)]
pub struct Message1 {
    pub r#type: u8,
    pub suite: u8,
    pub x_i: Vec<u8>,
    pub deveui: Vec<u8>,
    pub appeui: Vec<u8>
}

/// Serializes EDHOC `message_1`.
pub fn serialize_message_1(msg: &Message1) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the EDHOC message
    let raw_msg = (
        msg.r#type,
        msg.suite,
        Bytes::new(&msg.x_i),
        Bytes::new(&msg.deveui),
        Bytes::new(&msg.appeui)
    );

    Ok(cbor::encode_sequence(raw_msg)?)
}

/// Deserializes EDHOC `message_1`.
pub fn deserialize_message_1(msg: &[u8]) -> Result<Message1> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
    let raw_msg: (u8, u8, ByteBuf, ByteBuf, ByteBuf) =
        cbor::decode_sequence(msg, 5, &mut temp)?;


    // On success, just move the items into the "nice" message structure

    Ok(Message1 {
        r#type: raw_msg.0,
        suite: raw_msg.1,
        x_i: raw_msg.2.into_vec(),
        deveui: raw_msg.3.into_vec(),
        appeui: raw_msg.4.into_vec(),
    })
}

/// EDHOC `message_2`.
/// * 
#[derive(Debug, PartialEq)]
pub struct Message2 {
    pub ephemeral_key_r: Vec<u8>,
    pub c_r: Vec<u8>,
    pub ciphertext2: Vec<u8>,
}

/// Serializes EDHOC `message_2`.
pub fn serialize_message_2(msg: &Message2) -> Result<Vec<u8>> {
    let c_r_and_ciphertext = [msg.c_r.clone(), msg.ciphertext2.clone()].concat();


let encoded = (
    Bytes::new(&msg.ephemeral_key_r),
    Bytes::new(&c_r_and_ciphertext),

);
    Ok(cbor::encode_sequence(encoded)?)
}

/// Deserializes EDHOC `message_2`.
pub fn deserialize_message_2(msg: &[u8]) -> Result<Message2> { //Result<Message2>
    let mut temp = Vec::with_capacity(msg.len() + 1);
    // First, attempt to decode the variant without c_u
    let (x_r, c_r_and_cipher2) = cbor::decode_sequence::<(ByteBuf, ByteBuf)>(msg, 2, &mut temp)?;

            

    let connection_id = &c_r_and_cipher2[..CONNECTION_IDENTIFIER_LENGTH];
    let ciphertext2 = &c_r_and_cipher2[CONNECTION_IDENTIFIER_LENGTH..];


    Ok(Message2 {
        ephemeral_key_r: x_r.to_vec(),
        c_r: connection_id.to_vec(),
        ciphertext2: ciphertext2.to_vec(),
        })


    
}

// derive_prk
//deriving PRK's from some salt, and a key (shared key)
pub fn derive_prk(
    salt: Option<&[u8]>, 
    ikm: &[u8]
) -> Result<(Vec<u8>,Hkdf<Sha256>)> {
    // This is the extract step, resulting in the pseudorandom key (PRK)
    let (prk, hkdf) = Hkdf::<Sha256>::extract(salt, ikm);
    let prk_array = prk.to_vec();

    Ok((prk_array,hkdf))
}
/// EDHOC `message_3`.
#[derive(Debug, PartialEq)]
pub struct Message3 {
    pub ciphertext: Vec<u8>,
}

/// Serializes EDHOC `message_3`.
pub fn serialize_message_3(msg: &Message3) -> Result<Vec<u8>> {
    Ok(cbor::encode(Bytes::new(&msg.ciphertext))?)

}

/// Deserializes EDHOC `message_3`.
pub fn deserialize_message_3(msg: &[u8]) -> Result<Message3> {


    let cpy = msg.to_vec();
    let ciphertext = cbor::decode::<ByteBuf>(&cpy)?;
    // If we managed this time, we can return the struct without c_v
    Ok(Message3 {
        ciphertext: ciphertext.into_vec(),
        })
    
}

#[derive(Debug, PartialEq)]
pub struct Message4 {
    pub ciphertext: Vec<u8>,
}

/// Serializes EDHOC `message_3`.
pub fn serialize_message_4(msg: &Message4) -> Result<Vec<u8>> {
    Ok(cbor::encode(Bytes::new(&msg.ciphertext))?)

}

/// Deserializes EDHOC `message_3`.
pub fn deserialize_message_4(msg: &[u8]) -> Result<Message4> {


    let cpy = msg.to_vec();
    let ciphertext = cbor::decode::<ByteBuf>(&cpy)?;
    // If we managed this time, we can return the struct without c_v
    Ok(Message4 {
        ciphertext: ciphertext.into_vec(),
        })
    
}

/// Returns the bytes of an EDHOC error message with the given text.
pub fn build_error_message(err_msg: &str) -> Vec<u8> {

    // Build a tuple for the sequence of items
    // (type, err_msg)
    let raw_msg = (-1, err_msg);


    // Try to serialize the message. If we fail for some reason, return a
    // valid, pregenerated error message saying as much.
    cbor::encode_sequence(raw_msg).unwrap_or_else(|_| {
        vec![
            0x20, 0x78, 0x22, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x77, 0x68,
            0x69, 0x6C, 0x65, 0x20, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x69, 0x6E,
            0x67, 0x20, 0x65, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x6D, 0x65, 0x73,
            0x73, 0x61, 0x67, 0x65,
        ]
    })
}

/// Returns the extracted message from the EDHOC error message.
pub fn extract_error_message(msg: &[u8]) -> Result<String> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
    let (_, err_msg): (isize, String) =
        cbor::decode_sequence(msg, 2, &mut temp)?;

    Ok(err_msg)
}

/// Returns `Error::Edhoc` variant containing the error message, if the given
/// message was an EDHOC error message.
///
/// Use it by passing a received message to it, before trying to parse it.
pub fn fail_on_error_message(msg: &[u8]) -> Result<()> {
    match extract_error_message(msg) {
        // If we succeed, it really is an error message
        Ok(err_msg) => Err(Error::Edhoc(err_msg)),
        // If not, then we don't have an error message
        Err(_) => Ok(()),
    }
}
/*/// Simple prk generation function

pub fn HKDFextract(
    salt : Option<&[u8]>, 
    secret: &[u8],
) -> Result<(GenericArray<u8, 10::OutputSize>,Hkdf<Sha256>)> {

    // This is the extract step, resulting in the pseudorandom key (PRK)
    let (material, PRK) = Hkdf::extract(salt, secret);
    // Expand the PRK to the desired length output keying material (OKM)

    Ok((material,  PRK))
}*/
/// The `EDHOC-Key-Derivation` function.
///
/// # Arguments
/// * `algorithm_id` - The algorithm name, e.g. "IV-GENERATION" or COSE number
///   e.g. "10" for AES-CCM-16-64-128.
/// * `key_data_length` - The desired key length in bits.
/// * `other` - Typically a transcript hash.
/// * `secret` - The ECDH shared secret to use as input keying material.
pub fn edhoc_key_derivation(
    algorithm_id: &str,
    key_data_length: usize,
    other: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>> {
    // We use the ECDH shared secret as input keying material
    let ikm = secret;
    // Since we have asymmetric authentication, the salt is 0
    let salt = None;
    // For the Expand step, take the COSE_KDF_Context structure as info
    let info = cose::build_kdf_context(algorithm_id, key_data_length, other)?;

    // This is the extract step, resulting in the pseudorandom key (PRK)
    let h = Hkdf::<Sha256>::new(salt, ikm);
    // Expand the PRK to the desired length output keying material (OKM)
    let mut okm = vec![0; key_data_length / 8];
    h.expand(&info, &mut okm)?;



    Ok(okm)
}


///Function for creating MAC tags for messages
///
/// # Arguments
/// * `PRK` - the prk used to create tag
/// * `maclength`  mac length given by cipher suite
/// * `th` transcript hash
/// * `id_cred_x` 
/// * `cred_x` 
/// 

pub fn create_macwith_expand(
    prk: Hkdf<Sha256>,
    maclength: usize,
    th: &[u8],
    mac_identifier : &str,
    id_cred_x : Vec<u8>,
    cred_x : Vec<u8>,
) -> Result<Vec<u8>> {

    // For the Expand step, take the COSE_KDF_Context structure as info
    let info = (
        th,
        mac_identifier,
        id_cred_x,
        cred_x,
    );
   let info_encoded =  cbor::encode_sequence(info)?;

    // Expand the PRK to the desired length output keying material (OKM)
    let mut okm = vec![0; maclength /8];

    prk.expand(&info_encoded, &mut okm)?;
    Ok(okm)
}


/// Generic acces to hkdf-expand Function for creating keystream2 and k_3 and IV_3
///
/// # Arguments
/// * `PRK` - the prk used to create tag
/// * `maclength`  mac length given by cipher suite
/// * `th` transcript hash (SAME th as in mac_2)
/// * identifier: string that identifies the value
/// 

pub fn generic_expand(
    prk: Hkdf<Sha256>,
    th: &[u8],
    length : usize,
    identifier : &str,
    is_bits :bool, 
) -> Result<Vec<u8>> {

    // For the Expand step, take the COSE_KDF_Context structure as info
    let info = (
        th,
        identifier,
        "",
    );
   let info_encoded =  cbor::encode_sequence(info)?;

    // Expand the PRK to the desired length output keying material (OKM)

    let k = if is_bits {
        8
      } else {
        1
      };
    let mut okm = vec![0; length / k] ;
    
    prk.expand(&info_encoded, &mut okm)?;
    Ok(okm)
}
pub fn tryexpand(
    prk: Hkdf<Sha256>,
    info1: &[u8],
    plain_text_length : usize,
) -> Result<Vec<u8>> {

    // For the Expand step, take the COSE_KDF_Context structure as info
    let info = (
        info1,
        "",
    );
   let info_encoded =  cbor::encode_sequence(info)?;

    // Expand the PRK to the desired length output keying material (OKM)
    let mut okm = vec![0; plain_text_length / 8];

    prk.expand(&info_encoded, &mut okm)?;
    Ok(okm)
}

pub fn tmp_encode(
    one : Vec<u8>,
    two : Vec<u8>,
) -> Result<Vec<u8>> {

    let info = (
        one,
        two
    );

   let info_encoded =  cbor::encode_sequence(info)?;

    Ok(info_encoded)
}

// Xor function, for message 2
pub fn xor(a : &Vec<u8>, b:&Vec<u8>) -> Result<Vec<u8>>{

    if a.len() != b.len(){
        panic!("Attempting to xor vec's of unequal length");
    }

    let c =  a.iter()
      .zip(b.iter())
      .map(|(&x1, &x2)| x1 ^ x2)
      .collect();
 
      Ok(c)
 }
/// The `EDHOC-Exporter` interface.
///
/// # Arguments
/// * `label` - Chosen by the application.
/// * `length` - The length in bytes (chosen by the application).
/// * `th_4` - TH_4.
/// * `secret` - The ECDH shared secret to use as input keying material.
pub fn edhoc_exporter(
    label: &str,
    length: usize,
    th_4: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>> {
    edhoc_key_derivation(label,  length, th_4, secret)
}

/// Calculates the transcript hash of the second message.
pub fn compute_th_2(
    message_1: Vec<u8>,
    c_r: &[u8],
    responder_ephemeral_pk: PublicKey,
) -> Result<Vec<u8>> {

    let msg_1_hash = h(&message_1)?;
    let pk_bytes = &responder_ephemeral_pk.to_bytes();

    let hash_data = cbor::encode_sequence((
        c_r,
        msg_1_hash,
        pk_bytes
    ))?;
    // Create a sequence of CBOR items from the data

    // Return the hash of this
    h(&hash_data)
}

/// Calculates the transcript hash of the third message.
pub fn compute_th_3(
    th_2: &[u8],
    ciphertext_2: &[u8],
) -> Result<Vec<u8>> {
    // Create a sequence of CBOR items
    let mut seq = Vec::new();
    // Add the items that are always present
    seq.extend(th_2);
    seq.extend(cbor::encode(Bytes::new(ciphertext_2))?);

    // Return the hash of this
    h(&seq)
}

/// Calculates the final transcript hash used for the `EDHOC-Exporter`.
pub fn compute_th_4(th_3: &[u8], ciphertext_3: &[u8]) -> Result<Vec<u8>> {
    // Create a sequence of CBOR items
    let mut seq = Vec::new();
    seq.extend(th_3);
    seq.extend(cbor::encode(Bytes::new(ciphertext_3))?);

    // Return the hash of this
    h(&seq)
}

/// Returns a CBOR bstr containing the hash of the input CBOR sequence.
fn h(seq: &[u8]) -> Result<Vec<u8>> {
    let mut sha256 = Sha256::default();
    sha256.input(seq);
    let hash: [u8; 32] = sha256.fixed_result().into();

    // Return the bstr encoding
    Ok(cbor::encode(Bytes::new(&hash))?)
}

/// Returns the CBOR bstr making up the plaintext of `message_i`.
pub fn build_plaintext(kid: &[u8], key: &[u8]) -> Result<Vec<u8>> {

    let concat = [key,kid].concat();
    Ok(concat.to_vec())
}

/// Extracts and returns the `kid` and signature from the plaintext of
/// `message_i`.
pub fn extract_plaintext(plaintext: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {

    let key = plaintext[..EDHOC_MAC/8].to_vec();
    let kid = plaintext[EDHOC_MAC/8..].to_vec();

    Ok((kid, key))
}

/// Encrypts and authenticates with AES-CCM-16-64-128.
///
/// DO NOT reuse the nonce with the same key.
pub fn aead_seal(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    // Initialize CCM mode
    let ccm: Ccm<Aes128, U8, U13> = Ccm::new(GenericArray::from_slice(key));

    
    // Encrypt and place ciphertext & tag in dst_out_ct
    let dst_out_ct = ccm.encrypt(
        GenericArray::from_slice(nonce),
        Payload {
            aad: ad,
            msg: plaintext,
        },
    )?;
    Ok(dst_out_ct)
}

/// Decrypts and verifies with AES-CCM-16-64-128.
pub fn aead_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    // Initialize CCM mode
    let ccm: Ccm<Aes128, U8, U13> = Ccm::new(GenericArray::from_slice(key));
    // Verify tag, if correct then decrypt and place plaintext in dst_out_pt
    let dst_out_pt = ccm.decrypt(
        GenericArray::from_slice(nonce),
        Payload {
            aad: ad,
            msg: ciphertext,
        },
    )?;

    Ok(dst_out_pt)
}


