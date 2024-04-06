**Describe the solution you'd like**
Publish the server side related to client [ start_tcp(server: ServerPtr, host: String)]
(https://github.com/rustdesk/rustdesk/blob/0d75f71d16b9712b959423f6ae8fe5de7502e8f2/src/rendezvous_mediator.rs#L334)

**Describe alternatives you've considered**
Forking the rustdesk-server for allowing tcp only handshake.  
RustDesk already have a option for allowing a tcp only handshake while it is compiled with `TEST_TCP` .  
It works perfectly with *hbbs / hbbr from rustdesk-server-pro docker image* but not with oss server.

After updating libs/hbb_common on rustdesk_server we can refactor the `handle_tcp` 

- It needs to use the new FramedStream with Option<Encrypt>
- It needs to send RendezvousMessage KeyExchange 
- It needs to send stream.set_key(Key) for enabling secure tcp

as a proof of concept I modified the RustDesk client for adding an option to choose between UDP and TCP mode.  
Next I quickly modified an oss rustdesk-server for working with this tcp enabled RustDesk client.
I added this when the tcp connection
```rust
let mut msg_out = RendezvousMessage::new();

let (key, sk) = Self::get_server_sk(&key);
match sk {
    Some(sk) => {
        let pk = sk.public_key();
        let m = pk.as_ref();
        let sm = sign::sign(m, &sk);

        let bytes_sm = Bytes::from(sm);
        msg_out.set_key_exchange(KeyExchange {
            keys: vec![bytes_sm],
            ..Default::default()
        });
        log::debug!(
            "KeyExchange {:?} -> bytes: {:?}",
            addr,
            hex::encode(Bytes::from(msg_out.write_to_bytes().unwrap()))
        );
        //stream.set_key(pk);
        Self::send_to_sink(&mut sink, msg_out).await;
    }
    None => {
    }
}
```
it sends a correct message to the client, the client answers also a KeyExchange message but with with two keys generated with [create_symmetric_key_msg(their_pk_b: [u8; 32])](https://github.com/rustdesk/rustdesk/blob/0d75f71d16b9712b959423f6ae8fe5de7502e8f2/src/common.rs#L1347) .
Basically it creates a symetric key with sodiumoxide, encrypt it with the server ed25519 public key and our ed25519 private key.  
The server receive the KeyExchange, because it has 2 keys, it decrypts the sodiumoxide secret box with client pk and server sk , get the symetric key and issue `stream.set_key(pk);`. 
Now the 21116 tcp port is secured and it can handle RegisterPeer…

**Additional context**
Add any other context about the feature request here.

**Notes**
 - Please write in english only. If you provide some images in different languages, you're required to write a translation in english.
 - In any case, **NEVER** put here the content if your `id_ed25519` file
 