use hbb_common::{
    bytes::{self, BytesMut}, protobuf::Message as _, rendezvous_proto::*, sodiumoxide::hex, tcp::{new_listener, FramedStream}, tokio, udp::FramedSocket
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut socket = FramedSocket::new("0.0.0.0:21116").await.unwrap();
    let listener = new_listener("0.0.0.0:21116", false).await.unwrap();
    let rlistener = new_listener("0.0.0.0:21117", false).await.unwrap();
    let mut id_map = std::collections::HashMap::new();
    let relay_server = std::env::var("IP").unwrap();
    let mut saved_stream = None;
    loop {
        tokio::select! {
            Some(Ok((bytes, addr))) = socket.next() => {
                handle_udp(&mut socket, bytes, addr.into(), &mut id_map).await;
            }
            Ok((stream, addr)) = listener.accept() => {
                let mut stream = FramedStream::from(stream,addr);
                if let Some(Ok(bytes)) = stream.next_timeout(3000).await {
                    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                        match msg_in.union {
                            Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                                println!("punch_hole_request {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                                if let Some(addr) = id_map.get(&ph.id) {
                                    let mut msg_out = RendezvousMessage::new();
                                    msg_out.set_request_relay(RequestRelay {
                                        relay_server: relay_server.clone(),
                                        ..Default::default()
                                    });
                                    println!("punch_hole_request {:?} -> bytes: {:?}", addr, hex::encode(&bytes));
                                    socket.send(&msg_out, addr.clone()).await.ok();
                                    saved_stream = Some(stream);
                                }
                            }
                            Some(rendezvous_message::Union::RelayResponse(_)) => {
                                println!("relay_response {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                                let mut msg_out = RendezvousMessage::new();
                                msg_out.set_relay_response(RelayResponse {
                                    relay_server: relay_server.clone(),
                                    ..Default::default()
                                });
                                if let Some(mut stream) = saved_stream.take() {
                                    stream.send(&msg_out).await.ok();
                                    if let Ok((stream_a, _)) = rlistener.accept().await {
                                        let mut stream_a = FramedStream::from(stream_a,addr);
                                        stream_a.next_timeout(3_000).await;
                                        if let Ok((stream_b, _)) = rlistener.accept().await {
                                            let mut stream_b = FramedStream::from(stream_b,addr);
                                            stream_b.next_timeout(3_000).await;
                                            relay(stream_a, stream_b, &mut socket, &mut id_map).await;
                                        }
                                    }
                                }
                            }
                            _ => {
                                println!("unknown RendezvousMessage in tcp {:?}", hex::encode(&bytes));
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
                println!("register_peer {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                id_map.insert(rp.id, addr);
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_peer_response(RegisterPeerResponse::new());
                println!("register_peer {:?} -> bytes: {:?}",addr,hex::encode(bytes::Bytes::from(msg_out.write_to_bytes().unwrap())));
                socket.send(&msg_out, addr).await.ok();
            }
            Some(rendezvous_message::Union::RegisterPk(_)) => {
                println!("register_pk {:?} <- bytes: {:?}", addr, hex::encode(&bytes));
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_pk_response(RegisterPkResponse {
                    result: register_pk_response::Result::OK.into(),
                    ..Default::default()
                });
                println!("register_pk {:?} -> bytes: {:?}",addr,hex::encode(bytes::Bytes::from(msg_out.write_to_bytes().unwrap())));
                socket.send(&msg_out, addr).await.ok();
            }
            _ => {
                println!("unknown message {:?}", hex::encode(&bytes));
            }
        }
    }
}
