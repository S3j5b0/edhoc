//#![no_std]

use edhoc::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI, PartyR,
    
};

use x25519_dalek_ng::{PublicKey,StaticSecret};

use rand_core::{OsRng,RngCore};


const SUITE_I: u8 = 0;
const METHOD_TYPE_I : u8 = 3;


fn main() {
    /*
    Parti I generate message 1
    */


    let i_static_priv : StaticSecret  = StaticSecret::new(OsRng);
    let i_static_pub = PublicKey::from(&i_static_priv);


    // Party U ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let mut i_priv = [0u8; 32];
    OsRng.fill_bytes(&mut i_priv);
    
    // Choose a connection identifier
    let deveui = [0x1,1,2,3,2,4,5,7].to_vec();
    let appeui = [0,1,2,3,4,5,6,7].to_vec();


    let i_kid = [0xA2].to_vec(); 
    let msg1_sender =
        PartyI::new(deveui,Some(appeui), i_priv, i_static_priv, i_static_pub, i_kid);


    let (msg1_bytes, msg2_receiver) =
        // If an error happens here, we just abort. No need to send a message,
        // since the protocol hasn't started yet.
        msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();
 
    println!("msg1len {}", msg1_bytes.len());
    /*
    /// Party R handle message 1
    */

    let r_static_priv : StaticSecret  = StaticSecret::new(OsRng);
    let r_static_pub = PublicKey::from(&r_static_priv);


    let r_kid = [0x10].to_vec();

    // create keying material

    let mut r_priv = [0u8;32];

    OsRng.fill_bytes(&mut r_priv);

    let msg1_receiver =
       PartyR::new(r_priv, r_static_priv, r_static_pub, r_kid);
       
    let (msg2_sender,devui,appeui) = match msg1_receiver.handle_message_1_ead(msg1_bytes) {
        Err(OwnError(b)) => {
            panic!("{:?}", b)
        },
        Ok(val) => val,
    };


    // AS should now validate deveui and appeui
    let (msg2_bytes,msg3_receiver) = match msg2_sender.generate_message_2(appeui.unwrap(),None) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };
    println!("msg2len {} ", msg2_bytes.len());

    /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 2, and then generating message 3, and the rck/sck
    ///////////////////////////////////////////////////////////////////// */
    

    // unpacking message, and getting kid, which we in a realworld situation would use to lookup our key
    let  (r_kid ,ad_r ,msg2_verifier) = match msg2_receiver.unpack_message_2_return_kid(msg2_bytes){
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };


    let msg3_sender = match msg2_verifier.verify_message_2(r_static_pub.as_bytes()) {
        Err(OwnError(b)) => panic!("Send these bytes: {:?}", &b),
        Ok(val) => val, };

    let (msg4_receiver_verifier, msg3_bytes) =
        match msg3_sender.generate_message_3(None) {
            Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
            Ok(val) => val,
        };

    /*///////////////////////////////////////////////////////////////////////////
    /// Responder receiving and handling message 3, and generating message4 and sck rck
    ///////////////////////////////////////////////////////////////////// */
    
    let (msg3verifier, kid) = match  msg3_receiver.unpack_message_3_return_kid(msg3_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };

    let (msg4_sender, master_secret_r, master_salt_r) = match msg3verifier.verify_message_3(i_static_pub.as_bytes())
    {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };

     /*///////////////////////////////////////////////////////////////////////////
    /// now the AS uses the kid to retrieve the right static public key
    ///////////////////////////////////////////////////////////////////// */



    let msg4_bytes =
    match msg4_sender.generate_message_4(None) {
            Err(OwnOrPeerError::PeerError(s)) => {
                panic!("Received error msg: {}", s)
            }
            Err(OwnOrPeerError::OwnError(b)) => {
                panic!("Send these bytes: {}", hexstring(&b))
            }
            Ok(val) => val,
        };
        println!("msg4 {}", msg4_bytes.len());

    /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 4, and generate  sck and rck. Then all is done
    ///////////////////////////////////////////////////////////////////// */

    let (master_secret_i,master_salt_i) =
    match msg4_receiver_verifier.handle_message_4(msg4_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    println!("Initiator completed handshake and made chan keys");

    println!("initiatir secret {:?}", master_secret_i);
    println!("initiator salt {:?}", master_salt_i);
    println!("Responder completed handshake and made chan keys");

    println!("Responder secret {:?}", master_secret_r);
    println!("rck {:?}", master_salt_i);
    

}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
