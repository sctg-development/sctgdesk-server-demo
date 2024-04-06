use hbb_common::protobuf::Message;
use hbb_common::{
    bytes::{self, Bytes, BytesMut},
    rendezvous_proto::*,
    sodiumoxide::{
        base64,
        crypto::{box_, sign},
        hex,
    },
    tcp::{new_listener, FramedStream},
    timeout, tokio,
    udp::FramedSocket,
};
use hbb_common::{lazy_static::lazy_static, sodiumoxide::crypto::secretbox};
use std::net::SocketAddr;

lazy_static! {
    static ref KEYPAIR: (box_::PublicKey, box_::SecretKey) = box_::gen_keypair();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut socket = FramedSocket::new("0.0.0.0:21116").await.unwrap();
    let nat_listener = new_listener("0.0.0.0:21115", false).await.unwrap();
    let listener = new_listener("0.0.0.0:21116", false).await.unwrap();
    let relay_listener = new_listener("0.0.0.0:21117", false).await.unwrap();
    let mut id_map = std::collections::HashMap::new();
    let relay_server = std::env::var("IP").unwrap();
    //let mut saved_stream = None;
    let mut phase1_done = false;
    loop {
        tokio::select! {
            Some(Ok((bytes, addr))) = socket.next() => {
                handle_udp(&mut socket, bytes, addr.into(), &mut id_map).await;
            }
            Ok((stream, addr)) = nat_listener.accept() => {
                let mut stream = FramedStream::from(stream,addr);

                if let Some(Ok(bytes)) = stream.next_timeout(3000).await {
                    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                        match msg_in.union {
                            Some(rendezvous_message::Union::TestNatRequest(_)) => {
                                println!("TestNatRequest on nat port {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                                let mut msg_out = RendezvousMessage::new();
                                let res = TestNatResponse {
                                    port: addr.port() as _,
                                    ..Default::default()
                                };
                                msg_out.set_test_nat_response(res);
                                println!(
                                    "TestNatRequest on nat port {:?} -> bytes: {:?}",
                                    addr,
                                    hex::encode(bytes::Bytes::from(msg_out.write_to_bytes().unwrap()))
                                );
                                stream.send(&msg_out).await.ok();
                            },
                            _ => {
                                println!("unknown RendezvousMessage {:?} in tcp {:?}",msg_in, hex::encode(&bytes));
                            }
                        }
                    }

                }
            }
            Ok((stream, addr)) = listener.accept() => {
                let mut stream = FramedStream::from(stream, addr);
                // TCP secure handshake send our temporary public key in a KeyExchange message
                if !phase1_done
                {
                    key_exchange_phase1( addr, &mut stream).await;
                    phase1_done = true;
                }
                while let Ok(Some(Ok(bytes))) = timeout(30_000, stream.next()).await {
                    if !stream.is_secured() && phase1_done {
                        // handle KeyExchange phase 2
                        key_exchange_phase2(addr, &mut stream, &bytes).await;
                        println!("Is connection secured: {:?}", stream.is_secured());
                    }
                // }
                // if let Some(Ok(bytes)) = stream.next_timeout(3000).await {
                    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                        match msg_in.union {
                            Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                                println!("PunchHoleRequest {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                                if let Some(addr) = id_map.get(&ph.id) {
                                    let mut msg_out = RendezvousMessage::new();
                                    msg_out.set_request_relay(RequestRelay {
                                        relay_server: relay_server.clone(),
                                        ..Default::default()
                                    });
                                    println!("PunchHoleRequest {:?} -> bytes: {:?}", addr, hex::encode(&bytes));
                                    socket.send(&msg_out, addr.clone()).await.ok();
                                    // saved_stream = Some(stream);
                                }
                            }
                            Some(rendezvous_message::Union::RelayResponse(_)) => {
                                println!("RelayResponse {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                                let mut msg_out = RendezvousMessage::new();
                                msg_out.set_relay_response(RelayResponse {
                                    relay_server: relay_server.clone(),
                                    ..Default::default()
                                });
                                //if let Some(mut stream) = saved_stream.take() {
                                    stream.send(&msg_out).await.ok();
                                    if let Ok((stream_a, _)) = relay_listener.accept().await {
                                        let mut stream_a = FramedStream::from(stream_a,addr);
                                        stream_a.next_timeout(3_000).await;
                                        if let Ok((stream_b, _)) = relay_listener.accept().await {
                                            let mut stream_b = FramedStream::from(stream_b,addr);
                                            stream_b.next_timeout(3_000).await;
                                            relay(stream_a, stream_b, &mut socket, &mut id_map).await;
                                        }
                                    }
                                //}
                            }
                            Some(rendezvous_message::Union::RegisterPeer(_)) => {
                                println!("RegisterPeer {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                            }
                            Some(rendezvous_message::Union::RegisterPk(_)) => {
                                println!("RegisterPk {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                                let mut msg_out = RendezvousMessage::new();
                                msg_out.set_register_pk_response(RegisterPkResponse {
                                    result: register_pk_response::Result::OK.into(),
                                    ..Default::default()
                                });
                                println!(
                                    "RegisterPk {:?} -> bytes: {:?}",
                                    addr,
                                    hex::encode(bytes::Bytes::from(msg_out.write_to_bytes().unwrap()))
                                );
                                let _ = stream.send(&msg_out).await;
                            }
                            // Some(rendezvous_message::Union::KeyExchange(ex)) => {
                            //     println!("KeyExchange {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                            //     if ex.keys.len() != 2 {
                            //         println!("Handshake failed: invalid phase 2 key exchange message");
                            //         key_exchange_phase2(addr,&mut stream, &bytes).await;
                            //     }
                            // }
                            Some(rendezvous_message::Union::RequestRelay(_)) => {
                                println!("RequestRelay {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                            }
                            Some(rendezvous_message::Union::SoftwareUpdate(_)) => {
                                println!("SoftwareUpdate {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                            }
                            Some(rendezvous_message::Union::TestNatRequest(_)) => {
                                println!("TestNatRequest {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                                let mut msg_out = RendezvousMessage::new();
                                let res = TestNatResponse {
                                    port: addr.port() as _,
                                    ..Default::default()
                                };
                                msg_out.set_test_nat_response(res);
                                println!(
                                    "TestNatRequest {:?} -> bytes: {:?}",
                                    addr,
                                    hex::encode(bytes::Bytes::from(msg_out.write_to_bytes().unwrap()))
                                );
                                stream.send(&msg_out).await.ok();
                                // socket.send(&msg_out, addr).await.ok();
                            }
                            Some(rendezvous_message::Union::PeerDiscovery(_)) => {
                                println!("PeerDiscovery {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                            }
                            Some(rendezvous_message::Union::OnlineRequest(_)) => {
                                println!("OnlineRequest {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                            }
                            Some(rendezvous_message::Union::FetchLocalAddr(_)) => {
                                println!("FetchLocalAddr {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                            }
                            Some(rendezvous_message::Union::PunchHole(_)) => {
                                println!("PunchHole {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                            }
                            _ => {
                                println!("unknown RendezvousMessage {:?} in tcp {:?}",msg_in, hex::encode(&bytes));
                            }
                        }
                    }else{
                        println!("unknown TCP message {:?}", hex::encode(&bytes));
                    }
                }
            }
        }
    }
}

async fn relay(
    stream: FramedStream,
    peer: FramedStream,
    socket: &mut FramedSocket,
    id_map: &mut std::collections::HashMap<String, std::net::SocketAddr>,
) {
    let mut peer = peer;
    let mut stream = stream;
    peer.set_raw();
    stream.set_raw();
    loop {
        tokio::select! {
            Some(Ok((bytes, addr))) = socket.next() => {
                println!("received udp {:?}", hex::encode(&bytes));
                handle_udp(socket, bytes, addr.into(), id_map).await;
            }
            res = peer.next() => {
                if let Some(Ok(bytes)) = res {
                    println!("send udp {:?}", hex::encode(&bytes));
                    stream.send_bytes(bytes.into()).await.ok();
                } else {
                    break;
                }
            },
            res = stream.next() => {
                if let Some(Ok(bytes)) = res {
                    peer.send_bytes(bytes.into()).await.ok();
                } else {
                    break;
                }
            },
        }
    }
}

async fn handle_udp(
    socket: &mut FramedSocket,
    bytes: BytesMut,
    addr: std::net::SocketAddr,
    id_map: &mut std::collections::HashMap<String, std::net::SocketAddr>,
) {
    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
        match msg_in.union {
            Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                println!(
                    "RegisterPeer {:?} <- bytes: {:?}",
                    addr,
                    hex::encode(&bytes)
                );
                id_map.insert(rp.id, addr);
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_peer_response(RegisterPeerResponse::new());
                println!(
                    "RegisterPeer {:?} -> bytes: {:?}",
                    addr,
                    hex::encode(bytes::Bytes::from(msg_out.write_to_bytes().unwrap()))
                );
                socket.send(&msg_out, addr).await.ok();
            }
            Some(rendezvous_message::Union::RegisterPk(_)) => {
                println!("RegisterPk {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_pk_response(RegisterPkResponse {
                    result: register_pk_response::Result::OK.into(),
                    ..Default::default()
                });
                println!(
                    "RegisterPk {:?} -> bytes: {:?}",
                    addr,
                    hex::encode(bytes::Bytes::from(msg_out.write_to_bytes().unwrap()))
                );
                socket.send(&msg_out, addr).await.ok();
            }
            _ => {
                println!("unknown message {:?}", hex::encode(&bytes));
            }
        }
    }
}

fn get_server_sk() -> (String, Option<sign::SecretKey>) {
    let key = std::env::var("RS_PRIV_KEY").unwrap();
    if let Ok(sk_b) = base64::decode(&key, base64::Variant::Original) {
        let out_sk = sign::SecretKey::from_slice(&sk_b[..]);
        return (key, out_sk);
    }
    (key, None)
}

async fn key_exchange_phase1(addr: SocketAddr, connection: &mut FramedStream) {
    let mut msg_out = RendezvousMessage::new();

    let (_, sk) = get_server_sk();
    match sk {
        Some(sk) => {
            let (our_pk_b, _) = &*KEYPAIR;
            let sm = sign::sign(&our_pk_b.0, &sk);

            let bytes_sm = Bytes::from(sm);
            msg_out.set_key_exchange(KeyExchange {
                keys: vec![bytes_sm],
                ..Default::default()
            });
            println!(
                "KeyExchange {:?} -> bytes: {:?}",
                addr,
                hex::encode(Bytes::from(msg_out.write_to_bytes().unwrap()))
            );
            //TODO
            //Self::send_to_sink(sink, msg_out).await;
            let _ = connection.send(&msg_out).await;
        }
        None => {}
    }
}

async fn key_exchange_phase2(addr: SocketAddr, connection: &mut FramedStream, bytes: &BytesMut) {
    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
        match msg_in.union {
            Some(rendezvous_message::Union::KeyExchange(ex)) => {
                let (_, our_sk_b) = &*KEYPAIR;
                println!("KeyExchange {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                if ex.keys.len() != 2 {
                    println!("Handshake failed: invalid phase 2 key exchange message");
                    return;
                }

                println!("KeyExchange their_pk: {:?}", hex::encode(&ex.keys[0]));
                println!("KeyExchange box: {:?}", hex::encode(&ex.keys[1]));
                let their_pk: [u8; 32] = ex.keys[0].to_vec().try_into().unwrap();
                let cryptobox: [u8; 48] = ex.keys[1].to_vec().try_into().unwrap();
                let symetric_key = get_symetric_key_from_msg(our_sk_b.0, their_pk, &cryptobox);
                println!("KeyExchange symetric key: {:?}", hex::encode(&symetric_key));
                let key = secretbox::Key::from_slice(&symetric_key);
                match key {
                    Some(key) => {
                        connection.set_key(key);
                        println!("KeyExchange symetric key set");
                        return;
                    }
                    None => {
                        println!("KeyExchange symetric key NOT set");
                        return;
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn get_symetric_key_from_msg(
    our_sk_b: [u8; 32],
    their_pk_b: [u8; 32],
    sealed_value: &[u8; 48],
) -> [u8; 32] {
    let their_pk_b = box_::PublicKey(their_pk_b);
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sk = box_::SecretKey(our_sk_b);
    let key = box_::open(sealed_value, &nonce, &their_pk_b, &sk);
    match key {
        Ok(key) => {
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&key);
            key_array
        }
        Err(e) => panic!("Error while opening the seal key{:?}", e),
    }
}
