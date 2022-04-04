//#![no_std]

use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI, PartyR,
    
};
use rand::{rngs::StdRng, Rng,SeedableRng};

use x25519_dalek_ng::{PublicKey,StaticSecret};

use rand_core::{OsRng, RngCore};


const SUITE_I: u8 = 3;
const METHOD_TYPE_I : u8 = 0;


fn main() {


    /*
    Parti I generate message 1
    */


    let i_static_priv : StaticSecret  = StaticSecret::new(OsRng);
    let i_static_pub = PublicKey::from(&i_static_priv);


    // Party U ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let mut r : StdRng = StdRng::from_entropy();
    let i_priv = r.gen::<[u8;32]>();
    
    // Choose a connection identifier
    let deveui = [0x1,1,2,3,2,4,5,7].to_vec();
    let appeui = [0,1,2,3,4,5,6,7].to_vec();


    let i_kid = [0xA2].to_vec();
    let msg1_sender =
        PartyI::new(deveui,appeui, i_priv, i_static_priv, i_static_pub, i_kid);


    let (msg1_bytes, msg2_receiver) =
        // If an error happens here, we just abort. No need to send a message,
        // since the protocol hasn't started yet.
        msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();
 
    println!("msg1 {}", msg1_bytes.len());


  //  let msg_1_struct : Message1= util::deserialize_message_1(&msg1_bytes).unwrap();

    /*
    /// Party R handle message 1
    */

    let r_static_priv : StaticSecret  = StaticSecret::new(OsRng);
    let r_static_pub = PublicKey::from(&r_static_priv);


    let r_kid = [0xA3].to_vec();

    // create keying material

    let mut r2 : StdRng = StdRng::from_entropy();
    let r_priv = r2.gen::<[u8;32]>();

    let msg1_receiver =
       PartyR::new(r_priv, r_static_priv, r_static_pub, r_kid);
       
    let (msg2_sender,devui,appeui) = match msg1_receiver.handle_message_1(msg1_bytes) {
        Err(OwnError(b)) => {
            panic!("{:?}", b)
        },
        Ok(val) => val,
    };

    // AS should now validate deveui and appeui
    let (msg2_bytes,msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };

    println!("msg2 {}", msg2_bytes.len());

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

    println!("initiator unpacked responders kid: {:?}", r_kid);

    let msg3_sender = match msg2_verifier.verify_message_2(&r_static_pub.as_bytes().to_vec()) {
        Err(OwnError(b)) => panic!("Send these bytes: {:?}", &b),
        Ok(val) => val, };

    let (msg4_receiver_verifier, msg3_bytes) =
        match msg3_sender.generate_message_3() {
            Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
            Ok(val) => val,
        };
    println!("msg3 {}", msg3_bytes.len());

    /*///////////////////////////////////////////////////////////////////////////
    /// Responder receiving and handling message 3, and generating message4 and sck rck
    ///////////////////////////////////////////////////////////////////// */
    
    let tup3 = msg3_receiver.handle_message_3(msg3_bytes);

    let (msg3verifier, r_kid) = match tup3 {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };

    let (msg4_sender, as_sck, as_rck, as_rk) = match msg3verifier.verify_message_3(&i_static_pub.as_bytes().to_vec())
    {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };

    ///////
    /// now the AS uses the kid to retrieve the right static public key
    /// ///////////



        let msg4_bytes =
        match msg4_sender.generate_message_4() {
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
    /// Initiator receiving and handling message 4, and generati  sck and rck. Then all is done
    ///////////////////////////////////////////////////////////////////// */

    let (ed_sck, ed_rck,ed_rk) =
    match msg4_receiver_verifier.receive_message_4(msg4_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    println!("Initiator completed handshake and made chan keys");

    println!("sck {:?}", ed_sck);
    println!("rck {:?}", ed_rck);
    println!("rk ed {:?}", ed_rk);
    println!("Responder completed handshake and made chan keys");

    println!("sck {:?}", as_sck);
    println!("rck {:?}", as_rck);
    println!("as rk {:?}", as_rk);

}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
