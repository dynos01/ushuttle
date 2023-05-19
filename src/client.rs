use std::{
    error::Error,
    result,
    net::SocketAddr,
    sync::{Arc, Mutex},
    collections::HashMap,
    ops::Sub,
};
use log::{debug, info, warn};
use tokio::{
    net::{UdpSocket, TcpStream, tcp::{OwnedWriteHalf, OwnedReadHalf}},
    sync::oneshot::{self, error::TryRecvError},
    io::AsyncWriteExt,
    time::{sleep, Instant, Duration},
};
use flume::{Sender, Receiver};
use once_cell::sync::OnceCell;
use proxie::{Auth, Proxy, HTTPProxy, SOCKS5Proxy, tokio::AsyncProxy};
use crate::Args;

type Result<T> = result::Result<T, Box<dyn Error>>;

const SUPPORTED_PROXY: [&str; 2] = ["SOCKS5", "HTTP"];

static SOURCE_MAP: OnceCell<Mutex<HashMap<u32, (SocketAddr, usize, Instant)>>> = OnceCell::new();
static CONNECTIONS: OnceCell<Mutex<Vec<Sender<(Vec<u8>, SocketAddr)>>>> = OnceCell::new();
static SHUTDOWN: OnceCell<Mutex<Vec<oneshot::Receiver<()>>>> = OnceCell::new();

#[derive(thiserror::Error, Debug)]
pub(crate) enum ProxyParseError {
    #[error("Invalid proxy type, current supported: {:?}", SUPPORTED_PROXY)]
    InvalidProtocolError,
    #[error("Invalid proxy string, correct format: protocol://[user:pass@]host:port")]
    InvalidProxyError,
}

pub(crate) async fn start_client(args: Args) -> Result<()> {
    let addr: SocketAddr = args.listen.parse()?;
    let socket = UdpSocket::bind(addr).await?;
    let socket = Arc::new(socket);
    info!("Client listening on {addr}");

    let proxy: Option<Proxy> = match args.proxy {
        Some(proxy) => {
            let proxy = match parse_proxy(proxy) {
                Ok(proxy) => proxy,
                Err(e) => return Err(e),
            };
            match proxy {
                Proxy::HTTP(_) => info!("Using HTTP proxy"),
                Proxy::SOCKS5(_) => info!("Using SOCKS5 proxy"),
            };
            Some(proxy)
        },
        None => {
            info!("Using direct TCP connection");
            None
        },
    };

    let n_connection = match args.connection {
        Some(n) => n,
        None => crate::CONNECTIONS_DEFAULT,
    };

    SOURCE_MAP.get_or_init(|| {
        Mutex::new(HashMap::new())
    });

    CONNECTIONS.get_or_init(|| {
        Mutex::new(vec![])
    });

    SHUTDOWN.get_or_init(|| {
        Mutex::new(vec![])
    });

    let timeout = match args.timeout {
        Some(n) => n,
        None => crate::CLEAN_INTERVAL_DEFAULT,
    };

    let socket_clone = socket.clone();
    let proxy_clone = proxy.clone();
    tokio::spawn(async move {
        loop {
            let socket_clone = socket_clone.clone();
            let proxy_clone = proxy_clone.clone();
            match cleaner(timeout, socket_clone, proxy_clone).await {
                Ok(()) => {},
                Err(e) => warn!("Cleaner exited unexpectedly: {e}"),
            };
        }
    });

    let connections = match CONNECTIONS.get() {
        Some(connections) => connections,
        None => unreachable!(),
    };

    let shutdown = match SHUTDOWN.get() {
        Some(shutdown) => shutdown,
        None => unreachable!(),
    };

    for _ in 0..n_connection {
        let (tx, rx) = flume::unbounded();
        connections.lock()?.push(tx);
        loop {
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            shutdown.lock()?.push(shutdown_rx);
            match spawn_connection(rx.clone(), socket.clone(), proxy.clone(), shutdown_tx, timeout).await {
                Ok(()) => break,
                Err(e) => warn!("Failed to establish connection: {e}"),
            };
            sleep(Duration::from_secs(1)).await;
        }
    }

    let mut index: usize = 0;

    loop {
        let (packet, len, source) = crate::protocol::accept_udp_packet(&socket).await?;
        debug!("Got packet from udp://{source}, length = {len}");

        let source_hash = crc32fast::hash(&source.to_string().as_bytes());

        let index = {
            let source_map = match SOURCE_MAP.get() {
                Some(source_map) => source_map,
                None => unreachable!(),
            };
            let mut source_map = source_map.lock()?;

            match source_map.get(&source_hash) {
                Some(x) => {
                    let mut x = x.clone();
                    x.2 = Instant::now();
                    source_map.insert(source_hash, x);
                    x.1
                },
                None => {
                    debug!("Creating mapping for {source}");

                    let curr_index = index;
                    index = (index + 1) % n_connection;

                    source_map.insert(source_hash, (source, curr_index, Instant::now()));

                    curr_index
                },
            }
        };

        let packet = crate::protocol::build_tcp_packet(packet, len, source_hash);

        let connections = match CONNECTIONS.get() {
            Some(connections) => connections,
            None => unreachable!(),
        };

        let shutdown = match SHUTDOWN.get() {
            Some(shutdown) => shutdown,
            None => unreachable!(),
        };

        let closed = match shutdown.lock()?[index].try_recv() {
            Ok(_) => true,
            Err(TryRecvError::Empty) => false,
            Err(e) => {
                warn!("Failed to receive shutdown signal: {e}");
                continue;
            },
        };

        if closed { //Try to reconnect once if the connection is dead
            debug!("Connection {index} closed");
            let (tx, rx) = flume::unbounded();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            connections.lock()?[index] = tx;
            shutdown.lock()?[index] = shutdown_rx;
            match spawn_connection(rx.clone(), socket.clone(), proxy.clone(), shutdown_tx, timeout).await {
                Ok(()) => {},
                Err(e) => {
                    warn!("Failed to establish connection: {e}");
                    continue; //Failed to connect, sending on a dead connection is meaningless
                },
            };
        }

        match connections.lock()?[index].send((packet, source)) {
            Ok(()) => {},
            Err(e) => warn!("Failed to send shutdown signal: {e}"),
        };
    }
}

async fn spawn_connection(
    rx: Receiver<(Vec<u8>, SocketAddr)>,
    socket: Arc<UdpSocket>,
    proxy: Option<Proxy>,
    shutdown_tx: oneshot::Sender<()>,
    timeout: u64
) -> Result<()> {
    let remote = match crate::REMOTE.get() {
        Some(remote) => remote,
        None => unreachable!(),
    };

    let stream = match proxy {
        Some(proxy) => {
            let stream = match proxy {
                Proxy::HTTP(p) => p.connect(remote).await?,
                Proxy::SOCKS5(p) => p.connect(remote).await?,
            };
            stream.into_tcpstream()
        },
        None => TcpStream::connect(remote).await?,
    };

    let (mut stream_read, stream_write) = stream.into_split();

    tokio::spawn(async move {
        let (tx_close_send, rx_close_send) = oneshot::channel();
        let (tx_close_recv, rx_close_recv) = oneshot::channel();

        tokio::spawn(async move {
            match start_connection_send(rx, stream_write, remote).await {
                Ok(()) => {},
                Err(e) => {
                    warn!("Connection to {} failed: {e}", remote);
                    let _ = tx_close_send.send(());
                },
            };
        });

        tokio::spawn(async move {
            match start_connection_recv(&mut stream_read, socket, timeout).await {
                Ok(()) => {},
                Err(e) => {
                    warn!("Connection to {} failed: {e}", remote);
                    let _ = tx_close_recv.send(());
                },
            };
        });

        tokio::select! { //Terminate both sides if one side goes down
            _ = rx_close_send => {},
            _ = rx_close_recv => {},
        }

        debug!("One half of the TCP connection closed, closing another");
        let _ = shutdown_tx.send(());
    });

    Ok(())
}

async fn start_connection_send(
    rx: Receiver<(Vec<u8>, SocketAddr)>,
    mut stream: OwnedWriteHalf,
    remote: &String,
) -> Result<()> {
    let handshake_packet = crate::protocol::build_handshake()?;
    stream.write_all(&handshake_packet).await?;

    while let Ok((packet, source)) = rx.recv_async().await {
        debug!("Sending packet from udp://{source} to tcp://{remote}, length = {}", packet.len());
        stream.write_all(&packet).await?;
    }

    Ok(())
}

async fn start_connection_recv(
    stream: &mut OwnedReadHalf,
    socket: Arc<UdpSocket>,
    timeout: u64
) -> Result<()> {
    loop {
        let mut packet = crate::protocol::get_packet(stream, timeout, false).await?;

        let source_hash = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        packet.drain(..4);

        let source = {
            let source_map = match SOURCE_MAP.get() {
                Some(source_map) => source_map,
                None => unreachable!(),
            };
            let mut source_map = source_map.lock()?;
            match source_map.get(&source_hash) {
                Some(x) => {
                    let mut x = x.clone();
                    x.2 = Instant::now();
                    source_map.insert(source_hash, x);
                    x.0
                },
                None => {
                    warn!("Unknown source address");
                    continue;
                },
            }
        };

        debug!("Got packet to udp://{source}, length = {}", packet.len());
        socket.send_to(&packet, source).await?;
    }
}

async fn cleaner(timeout: u64, socket: Arc<UdpSocket>, proxy: Option<Proxy>) -> Result<()> {
    loop {
        sleep(Duration::from_secs(timeout)).await;

        let source_map = match SOURCE_MAP.get() {
            Some(source_map) => source_map,
            None => unreachable!(),
        };

        {
            let now = Instant::now();
            let mut source_map = source_map.lock()?;
            let length_orig = source_map.len();

            source_map.retain(|_, (_, _, last)| {
                let diff = now.sub(*last).as_secs();
                diff < timeout
            });
            let length_now = source_map.len();

            debug!("Cleaned {} mapping(s)", length_orig - length_now);
        }

        let connections = match CONNECTIONS.get() {
            Some(connections) => connections,
            None => unreachable!(),
        };

        let shutdown = match SHUTDOWN.get() {
            Some(shutdown) => shutdown,
            None => unreachable!(),
        };

        let connections_len = connections.lock()?.len();

        for index in 0..connections_len {
            let closed = match shutdown.lock()?[index].try_recv() {
                Ok(_) => true,
                Err(TryRecvError::Empty) => false,
                Err(TryRecvError::Closed) => true,
            };

            if closed { //Try to reconnect once if the connection is dead
                debug!("Connection {index} closed");
                let (tx, rx) = flume::unbounded();
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                connections.lock()?[index] = tx;
                shutdown.lock()?[index] = shutdown_rx;
                match spawn_connection(rx.clone(), socket.clone(), proxy.clone(), shutdown_tx, timeout).await {
                    Ok(()) => {},
                    Err(e) => warn!("Failed to establish connection: {e}"),
                };
            }
        }
    }
}

fn parse_proxy(proxy: String) -> Result<Proxy> {
    let mut proxy = proxy.to_lowercase();

    enum ProxyType {
        HTTP,
        SOCKS5,
    }

    let proxy_type = if proxy.starts_with("http://") {
        proxy.drain(..7);
        ProxyType::HTTP
    } else if proxy.starts_with("socks5://") {
        proxy.drain(..9);
        ProxyType::SOCKS5
    } else {
        return Err(Box::new(ProxyParseError::InvalidProtocolError));
    };

    let proxy: Vec<_> = proxy.split("@").collect();

    let (auth, proxy) = if proxy.len() == 1 {
        (None, proxy[0])
    } else if proxy.len() == 2 {
        let auth: Vec<_> = proxy[0].split(":").collect();
        if auth.len() != 2 {
            return Err(Box::new(ProxyParseError::InvalidProxyError));
        }

        (Some(Auth::new(auth[0], auth[1])), proxy[1])
    } else {
        return Err(Box::new(ProxyParseError::InvalidProxyError));
    };

    let server: SocketAddr = match proxy.parse() {
        Ok(server) => server,
        Err(_) => return Err(Box::new(ProxyParseError::InvalidProxyError)),
    };

    let host = &server.ip().to_string();
    let port = server.port();

    match proxy_type {
        ProxyType::HTTP => Ok(Proxy::HTTP(HTTPProxy::new(host, port, auth))),
        ProxyType::SOCKS5 => Ok(Proxy::SOCKS5(SOCKS5Proxy::new(host, port, auth))),
    }
}
