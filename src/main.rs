extern crate rand;
extern crate ed25519_dalek;
extern crate session_types;


use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyU, PartyV,
};
use sha2::Sha512;
use rand::rngs::OsRng;
use rand::{Rng, FromEntropy};
use rand::rngs::StdRng;
use ed25519_dalek::Keypair;
use session_types::*;
use std::thread;


type Server = Choose<Recv<Vec<u8>, Eps>, Offer<Send<Vec<u8>, Eps>, Choose<Recv<Vec<u8>, Eps>, Eps>>>;
type Client = <Server as HasDual>::Dual;


#[derive(Copy, Clone)]
struct KeyStorage {
    own_auth_public: [u8; 32],
    own_auth_private: [u8; 32],
    own_private: [u8; 32],
    other_auth_public: [u8; 32],
}

fn srv(c: Chan<(), Server>, info: KeyStorage) -> Vec<u8>  {
    let mut c = c;
    let mut msg1_bytes;
    // Choose a connection identifier
    let v_c_v = [0xC4, 0xC4, 0xC4, 0xC4, 0xC4, 0xC4, 0xC4, 0xC4, 0xC4, 0xC4, 0xC4].to_vec();
    // This is the keypair used to authenticate.
    // U must have the public key.
    let v_kid = [0xA3].to_vec();

    let msg1_receiver =
        PartyV::new(v_c_v, info.own_private, &info.own_auth_private, &info.own_auth_public, v_kid);

    // recieve message 1 with session types
    //let (c, msg1_bytes) = c.recv();
    

    offer! {c, 
        Vec => {
            let (c, msg1_bytes) = c.recv();//recv();
        },
        Quit => {
            c.close();
        }
    };
    
    
    let msg2_sender = match msg1_receiver.handle_message_1(msg1_bytes) {
        Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
        Ok(val) => val,
    };
    let (msg2_bytes, msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
        Ok(val) => val,
    };
    //send message 2 wih session type
    let c = c.sel1(); //.send(msg2_bytes);
    // recieve message 2 with session type
    let (c, msg3_bytes) = c.recv();
    // Party V ----------------------------------------------------------------
    let (_u_kid, msg3_verifier) =
        match msg3_receiver.extract_peer_kid(msg3_bytes) {
            Err(OwnOrPeerError::PeerError(s)) => {
                panic!("Received error msg: {}", s)
            }
            Err(OwnOrPeerError::OwnError(b)) => {
                panic!("Send these bytes: {}", hexstring(&b))
            }
            Ok(val) => val,
        };
    let (v_master_secret, v_master_salt) =
        match msg3_verifier.verify_message_3(&info.other_auth_public) {
            Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
            Ok(val) => val,
        };
    println!("v - \n{}\n{}", hexstring(&v_master_salt), hexstring(&v_master_secret));

    c.close();
    v_master_salt
}

fn cli(c: Chan<(), Client>, info: KeyStorage) -> Vec<u8> {
    let mut c = c;
    let mut msg2_bytes;
    // Choose a connection identifier
    let u_c_u = [0xC3].to_vec();

    let u_kid = [0xA2].to_vec();
    let msg1_sender =
        PartyU::new(u_c_u, info.own_private, &info.own_auth_private, &info.own_auth_public, u_kid);
    // type = 1 would be the case in CoAP, where party U can correlate
    // message_1 and message_2 with the token
    let (msg1_bytes, msg2_receiver) =
        // If an error happens here, we just abort. No need to send a message,
        // since the protocol hasn't started yet.
        msg1_sender.generate_message_1(1).unwrap();
        //let c = c.//c.sel1().send(msg1_bytes);
    c.sel1().send(msg1_bytes);
    
    let (c, msg2_bytes) = c.recv();
    // Party U ----------------------------------------------------------------
    let (_v_kid, msg2_verifier) =
    // This is a case where we could receive an error message (just abort
    // then), or cause an error (send it to the peer)
    match msg2_receiver.extract_peer_kid(msg2_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };
    let msg3_sender = match msg2_verifier.verify_message_2(&info.other_auth_public) {
    Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
    Ok(val) => val,
    };
    let (msg3_bytes, u_master_secret, u_master_salt) =
    match msg3_sender.generate_message_3() {
        Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
        Ok(val) => val,
    };
    let c = c.send(msg3_bytes);

    println!("u - \n{}\n{}", hexstring(&u_master_salt), hexstring(&u_master_secret));

    c.close();
    
    u_master_salt
}

fn main() {

    let mut csprng = OsRng::new().unwrap();
    let u_keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);
    let v_keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);

    let mut r : StdRng = StdRng::from_entropy();

    //alice_secret.to_bytes();

    let v_storage = KeyStorage {
        own_auth_public: v_keypair.public.to_bytes(),
        own_auth_private: v_keypair.secret.to_bytes(),
        own_private: r.gen::<[u8;32]>(),
        /*own_private: [
            0x17, 0xCD, 0xC7, 0xBC, 0xA3, 0xF2, 0xA0, 0xBD, 0xA6, 0x0C, 0x6D,
            0xE5, 0xB9, 0x6F, 0x82, 0xA3, 0x62, 0x39, 0xB4, 0x4B, 0xDE, 0x39,
            0x7A, 0x38, 0x62, 0xD5, 0x29, 0xBA, 0x8B, 0x3D, 0x7C, 0x62,
        ], // "Generate" an ECDH key pair (this is static, but MUST be ephemeral) */
        other_auth_public: u_keypair.public.to_bytes(),
    };

    let u_storage = KeyStorage {
        own_auth_public: u_keypair.public.to_bytes(),
        own_auth_private: u_keypair.secret.to_bytes(),
        own_private: r.gen::<[u8;32]>(),
        /*own_private: [
            0xD4, 0xD8, 0x1A, 0xBA, 0xFA, 0xD9, 0x08, 0xA0, 0xCC, 0xEF, 0xEF,
            0x5A, 0xD6, 0xB0, 0x5D, 0x50, 0x27, 0x02, 0xF1, 0xC1, 0x6F, 0x23,
            0x2C, 0x25, 0x92, 0x93, 0x09, 0xAC, 0x44, 0x1B, 0x95, 0x8E,
        ], // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)*/
        other_auth_public: v_keypair.public.to_bytes(),
    };

    println!("GENERATED KEYS\n--------------\nu_priv\n--------------\n{}\n--------------\nv_priv\n--------------\n{}\n",
                hexstring(&v_storage.own_auth_private), hexstring(&u_storage.own_auth_private));

    let (server_chan, client_chan) = session_channel();

    let srv_t = thread::spawn(move || srv(server_chan, v_storage));
    let cli_t = thread::spawn(move || cli(client_chan, u_storage));

    let (ser, cli) = (srv_t.join(), cli_t.join());
    //println!("{}", hexstring(&cli.unwrap()));
    let ser_unwrapped = ser.unwrap();
    let cli_unwrapped = cli.unwrap();
    assert_eq!(ser_unwrapped, cli_unwrapped, "We are testing {} with {}", hexstring(&ser_unwrapped), hexstring(&cli_unwrapped));
}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}