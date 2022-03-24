//#![no_std]

use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI, PartyR,
    
};
use rand::{rngs::StdRng, Rng,SeedableRng};

use x25519_dalek_ng::{PublicKey,StaticSecret};

use rand_core::OsRng;


const SUITE_I: isize = 3;
const METHOD_TYPE_I : isize = 0;
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
    let i_c_i = [0x1].to_vec();


    let i_kid = [0xA2].to_vec();
    let msg1_sender =
        PartyI::new(i_c_i, i_priv, i_static_priv, i_static_pub, i_kid);

    // type = 1 would be the case in CoAP, where party U can correlate
    // message_1 and message_2 with the token
    let (msg1_bytes, msg2_receiver) =
        // If an error happens here, we just abort. No need to send a message,
        // since the protocol hasn't started yet.
        msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();




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
       
    let msg2_sender = match msg1_receiver.handle_message_1(msg1_bytes) {
        Err(OwnError(b)) => {
            panic!("{:?}", b)
        },
        Ok(val) => val,
    };

    // generated shared secret for responder:
    // println!("{:?}", msg2_sender.0.shared_secret.to_bytes());

    /*
    Responder gør sig klar til at lave message 2.
    */

    let (msg2_bytes,msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };


    /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 2, and then generating message 3, and the rck/sck
    ///////////////////////////////////////////////////////////////////// */
    

    // unpacking message, and getting kid, which we in a realworld situation would use to lookup our key
    let  (r_kid ,msg2_verifier) = match msg2_receiver.unpack_message_2_return_kid(msg2_bytes){
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

    /*///////////////////////////////////////////////////////////////////////////
    /// Responder receiving and handling message 3, and generating message4 and sck rck
    ///////////////////////////////////////////////////////////////////// */
    
    let tup3 = msg3_receiver.handle_message_3(msg3_bytes,&i_static_pub.as_bytes().to_vec());

    let (msg4sender, r_sck,r_rck,rk) = match tup3 {
            Ok(v) => v,
            Err(e) =>panic!("panicking in handling message 3 {}", e),
        };

        let msg4_bytes =
        match msg4sender.generate_message_4() {
            Err(OwnOrPeerError::PeerError(s)) => {
                panic!("Received error msg: {}", s)
            }
            Err(OwnOrPeerError::OwnError(b)) => {
                panic!("Send these bytes: {}", hexstring(&b))
            }
            Ok(val) => val,
        };

        /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 4, and generati  sck and rck. Then all is done
    ///////////////////////////////////////////////////////////////////// */

    let (i_sck, i_rck,rk) =
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

    println!("sck {:?}", i_sck);
    println!("rck {:?}", i_rck);
    println!("Responder completed handshake and made chan keys");

    println!("sck {:?}", r_sck);
    println!("rck {:?}", r_rck);

}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
