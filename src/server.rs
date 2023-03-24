use std::{
    error::Error,
    result,
    net::{SocketAddr, ToSocketAddrs},
    collections::HashMap,
    sync::Arc,
    ops::Sub,
};
use log::{debug, info, warn};
use tokio::{
    net::{UdpSocket, TcpListener, tcp::{OwnedReadHalf, OwnedWriteHalf}},
    io::AsyncWriteExt,
    sync::Mutex,
    time::{sleep, Instant, Duration},
};
use flume::{Sender, Receiver};
use once_cell::sync::OnceCell;
use crate::Args;

type Result<T> = result::Result<T, Box<dyn Error>>;

static WORKERS: OnceCell<Mutex<HashMap<u32, (Sender<Vec<u8>>, Instant)>>> = OnceCell::new();

pub(crate) async fn start_server(args: Args) -> Result<()> {
    let addr: SocketAddr = args.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("Server listening on {addr}");

    WORKERS.get_or_init(|| {
        Mutex::new(HashMap::new())
    });

    let timeout = match args.timeout {
        Some(n) => n,
        None => crate::CLEAN_INTERVAL_DEFAULT,
    };

    tokio::spawn(async move {
        cleaner(timeout).await;
    });

    loop {
        let (stream, remote) = listener.accept().await?;

        tokio::spawn(async move {
            let (stream_read, stream_write) = stream.into_split();

            debug!("Got connection from tcp://{remote}");

            match process(stream_read, stream_write, remote, timeout).await {
                Ok(()) => {},
                Err(e) => warn!("{e}"),
            };
        });
    }
}

async fn process(
    mut stream_read: OwnedReadHalf,
    stream_write: OwnedWriteHalf,
    source: SocketAddr,
    timeout: u64
) -> Result<()> {
    let stream_write = Arc::new(Mutex::new(stream_write));
    let packet = crate::protocol::get_packet(&mut stream_read, timeout).await?;

    match crate::protocol::validate_handshake(&packet) {
        Ok(()) => {},
        Err(e) => {
            debug!("Authentication failure from {source}");
            return Err(e);
        },
    };
    debug!("Authentication success from {source}");

    loop {
        let mut packet = crate::protocol::get_packet(&mut stream_read, timeout).await?;

        let source_hash = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        packet.drain(..4);

        debug!("Got packet from tcp://{}, length = {}", source, packet.len());

        let workers = match WORKERS.get() {
            Some(workers) => workers,
            None => unreachable!(),
        };

        let tx = {
            let mut workers = workers.lock().await;
            let stream_write = stream_write.clone();

            match workers.get(&source_hash) {
                Some(x) => {
                    let res = x.0.clone();
                    let mut x = x.clone();
                    x.1 = Instant::now();
                    workers.insert(source_hash, x);
                    res
                },
                None => {
                    let (tx_send, rx_send) = flume::unbounded();
                    tokio::spawn(async move {
                        match spawn_relay_worker(rx_send, stream_write, source_hash).await {
                            Ok(()) => {},
                            Err(e) => warn!("{e}"),
                        };
                    });
                    workers.insert(source_hash, (tx_send.clone(), Instant::now()));
                    tx_send
                }
            }
        };

        tx.send_async(packet).await?;
    }
}

async fn spawn_relay_worker(
    rx: Receiver<Vec<u8>>,
    stream_write: Arc<Mutex<OwnedWriteHalf>>,
    source_hash: u32
) -> Result<()> {
    let remote = match crate::REMOTE.get() {
        Some(remote) => remote,
        None => unreachable!(),
    };
    let mut addrs = remote.to_socket_addrs()?;
    let remote_addr = match addrs.next() {
        Some(remote_addr) => remote_addr,
        None => return Err(Box::new(crate::protocol::ProtocolError::ResolutionError(remote.to_string()))),
    };

    let local_addr: SocketAddr = if remote_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;

    let socket = Arc::new(UdpSocket::bind(local_addr).await?);
    socket.connect(&remote_addr).await?;

    let socket_recv = socket.clone();
    let stream_write = stream_write.clone();
    tokio::spawn(async move {
        match spawn_relay_worker_recv(stream_write, socket_recv, source_hash).await {
            Ok(()) => {},
            Err(e) => warn!("{e}"),
        };
    });

    while let Ok(packet) = rx.recv_async().await {
        debug!("Sending packet to udp://{remote_addr}, length = {}", packet.len());
        socket.send(&packet).await?;
    }

    Ok(())
}

async fn spawn_relay_worker_recv(
    stream_write: Arc<Mutex<OwnedWriteHalf>>,
    socket: Arc<UdpSocket>,
    source_hash: u32
) -> Result<()> {
    let mut buf = [0u8; crate::BUFFER_SIZE];

    loop {
        let len = socket.recv(&mut buf).await?;
        let packet = crate::protocol::build_tcp_packet(buf.to_vec(), len, source_hash);

        {
            let mut stream_write = stream_write.lock().await;
            let peer = stream_write.peer_addr()?;
            debug!("Sending packet to tcp://{peer}, length = {len}");
            stream_write.write_all(&packet).await?;
        }
    }
}

async fn cleaner(timeout: u64) {
    loop {
        sleep(Duration::from_secs(timeout)).await;

        let workers = match WORKERS.get() {
            Some(workers) => workers,
            None => unreachable!(),
        };

        {
            let now = Instant::now();
            let mut workers = workers.lock().await;
            let length_orig = workers.len();

            workers.retain(|_, (_, last)| {
                let diff = now.sub(*last).as_secs();
                diff < timeout
            });
            let length_now = workers.len();

            debug!("Cleaned {} mapping(s)", length_orig - length_now);
        }
    }
}
