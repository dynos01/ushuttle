use std::{
    error::Error,
    result,
    time::{SystemTime, UNIX_EPOCH},
    net::SocketAddr,
};
use log::debug;
use tokio::{
    net::{UdpSocket, tcp::OwnedReadHalf},
    io::AsyncReadExt,
    time::{self, Duration, error::Elapsed},
};
use generic_array::GenericArray;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};

type Result<T> = result::Result<T, Box<dyn Error>>;

const AUTH_TIME_OFFSET_MAX: u64 = 30;
const UNIX_TIMESTAMP_LENGTH: usize = 8;

#[derive(thiserror::Error, Debug)]
pub(crate) enum ProtocolError {
    #[error("authentication failed")]
    AuthenticationError,
    #[error("connection failed")]
    ConnectionError,
    #[error("failed to resolve host {0}")]
    ResolutionError(String),
    #[error("failed to get complete packet: {0}")]
    IncompletePacket(Elapsed)
}

pub(crate) async fn get_packet(stream: &mut OwnedReadHalf, timeout: u64, is_handshake: bool) -> Result<Vec<u8>> {
    let mut buf = [0u8; crate::BUFFER_SIZE];

    let packet_len = if !is_handshake {
        stream.read_exact(&mut buf[..2]).await?;
        u16::from_be_bytes([buf[0], buf[1]])
    } else {
        let packet_len: u16;

        loop {
            let len = match time::timeout(
                Duration::from_secs(timeout),
                stream.read_exact(&mut buf[..2])
            ).await {
                Ok(res) => res?,
                Err(e) => return Err(Box::new(ProtocolError::IncompletePacket(e))),
            };

            if len != 2 {
                return Err(Box::new(ProtocolError::ConnectionError));
            }

            packet_len = u16::from_be_bytes([buf[0], buf[1]]);
            break;
        }

        packet_len
    };

    let packet_len = packet_len as usize;

    stream.read_exact(&mut buf[..packet_len]).await?;

    Ok(buf[..packet_len].to_vec())
}

pub(crate) fn validate_handshake(packet: &[u8]) -> Result<()> {
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let hashed_key = match crate::HASHED_KEY.get() {
        Some(key) => key,
        None => unreachable!(),
    };
    let cipher = ChaCha20Poly1305::new_from_slice(hashed_key)?;
    let packet = &packet[16..]; //Drop reserved 16 bytes for now
    let nonce = GenericArray::clone_from_slice(&packet[..12]);
    let packet = &packet[12..];
    let packet = cipher.decrypt(&nonce, packet)?;

    if packet.len() != UNIX_TIMESTAMP_LENGTH { //Should get a UNIX timestamp, which is 8 bytes
        debug!("Handshake packet too small");
        return Err(Box::new(ProtocolError::AuthenticationError));
    }

    let received_time = u64::from_be_bytes([
        packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]
    ]);

    if current_time.abs_diff(received_time) > AUTH_TIME_OFFSET_MAX {
        debug!(
            "Timestamp mismatch. Current: {}, received: {}, maximum offset: {}",
            current_time,
            received_time,
            AUTH_TIME_OFFSET_MAX
        );
        return Err(Box::new(ProtocolError::AuthenticationError));
    }

    Ok(())
}

pub(crate) async fn accept_udp_packet(socket: &UdpSocket) -> Result<(Vec<u8>, usize, SocketAddr)> {
    let mut buf = [0u8; 2 + crate::BUFFER_SIZE];
    let (len, remote) = socket.recv_from(&mut buf[2..]).await?;
    Ok((buf[2..2 + len].to_vec(), len, remote))
}

pub(crate) fn build_tcp_packet(packet: Vec<u8>, len: usize, source_hash: u32) -> Vec<u8> {
    let source_hash = source_hash.to_be_bytes().to_vec();

    //A UDP packet won't be longer than 2 ^ 16
    //Extra 4 bytes are for the hash
    let mut res = ((len + 4) as u16).to_be_bytes().to_vec();
    res.extend(source_hash);
    res.extend(packet);

    res[..2 + 4 + len].to_vec()
}

pub(crate) fn build_handshake() -> Result<Vec<u8>> {
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let hashed_key = match crate::HASHED_KEY.get() {
        Some(key) => key,
        None => unreachable!(),
    };

    let cipher = ChaCha20Poly1305::new_from_slice(hashed_key)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, current_time.to_be_bytes().as_ref())?;

    //Extra 12 bytes are for the nonce, 16 bytes for reserved message
    let mut packet = ((encrypted.len() + 12 + 16) as u16).to_be_bytes().to_vec();
    packet.extend(vec![0u8; 16]);
    packet.extend(nonce.to_vec());
    packet.extend(encrypted);

    Ok(packet)
}
