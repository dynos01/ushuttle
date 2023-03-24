mod server;
mod client;
mod protocol;

use std::{
    env,
    process::exit,
};
use log::{debug, info, warn, error};
use clap::Parser;
use once_cell::sync::OnceCell;

const NAME: &str = "ushuttle";
const VERSION: &str = "1.0.0";
const DESCRIPTION: &str = "Tunnel UDP packets through TCP SOCKS5/HTTP proxy server.";
const CONNECTIONS_DEFAULT: usize = 4;
const CLEAN_INTERVAL_DEFAULT: u64 = 30;
const BUFFER_SIZE: usize = 65535;

static HASHED_KEY: OnceCell<Vec<u8>> = OnceCell::new();
static REMOTE: OnceCell<String> = OnceCell::new();

#[derive(Parser)]
#[command(name = NAME)]
#[command(version = VERSION)]
#[command(about = DESCRIPTION, long_about = None)]
struct Args {
    /// Run in server or client mode
    #[arg(short, long, value_name = "server|client")]
    mode: String,

    /// Listen on address
    #[arg(short, long, value_name = "IP:port")]
    listen: String,

    /// Remote address
    #[arg(short, long, value_name = "IPv4|IPv6|hostname:port")]
    remote: String,

    /// Use proxy server, only valid in client
    #[arg(short, long, value_name = "protocol://[user:pass@]host:port")]
    proxy: Option<String>,

    #[arg(
        short,
        long,
        value_name = "n",
        help = format!("Number of connections, only valid in client (default = {CONNECTIONS_DEFAULT})")
    )]
    connection: Option<usize>,

    /// Preshared authentication key
    #[arg(short, long, value_name = "PSK")]
    key: String,

    #[arg(
        short,
        long,
        value_name = "n",
        help = format!("Timeout before closing unhealthy socket in second(s) (default = {CLEAN_INTERVAL_DEFAULT})")
    )]
    timeout: Option<u64>,

    /// Enable debug output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.verbose {
        env::set_var("RUST_LOG", "debug");
    } else {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    info!("Starting {NAME} version {VERSION}");

    if args.verbose {
        warn!("Verbose output enabled");
    }

    //Ensure the key length is 256 bits
    HASHED_KEY.get_or_init(|| {
        let hash = sha256::digest(args.key.clone());
        debug!("Key: {}, SHA256: {hash}", args.key);
        let res = (0..hash.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hash[i..i + 2], 16))
            .collect();
        match res {
            Ok(res) => res,
            Err(e) => {
                error!("{e}");
                exit(1);
            }
        }
    });

    info!("Remote: {}", args.remote);
    REMOTE.get_or_init(|| {
        args.remote.clone()
    });

    if args.mode == "server" {
        info!("Running in server mode");

        if !args.proxy.is_none() {
            error!("\"-p/--proxy\" can only be used in client mode");
            exit(1);
        }

        if !args.connection.is_none() {
            error!("\"-c/--connection\" can only be used in client mode");
            exit(1);
        }

        match server::start_server(args).await {
            Ok(()) => {},
            Err(e) => {
                error!("{e}");
                exit(1);
            },
        };
    } else if args.mode == "client" {
        info!("Running in client mode");

        match client::start_client(args).await {
            Ok(()) => {},
            Err(e) => {
                error!("{e}");
                exit(1);
            },
        };
    } else {
        error!("Available modes: \"server\", \"client\". Got \"{}\"", args.mode);
        exit(1);
    }
}
