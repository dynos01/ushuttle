mod server;
mod client;
mod protocol;

use std::{
    env,
    process::exit,
};
use chrono::Local;
use fern::colors::{Color, ColoredLevelConfig};
use log::{debug, info, warn, error, LevelFilter, Level};
use clap::Parser;
use once_cell::sync::OnceCell;

const CONNECTIONS_DEFAULT: usize = 4;
const CLEAN_INTERVAL_DEFAULT: u64 = 30;
const BUFFER_SIZE: usize = 65535;

static HASHED_KEY: OnceCell<Vec<u8>> = OnceCell::new();
static REMOTE: OnceCell<String> = OnceCell::new();

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"), long_about = None)]
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

fn setup_logger(log_level: LevelFilter) -> Result<(), fern::InitError> {
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Magenta)
        .trace(Color::BrightBlue);

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}{} {}] {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                colors.color(record.level()),
                if record.level() == Level::Info || record.level() == Level::Warn {
                    " "
                } else {
                    ""
                },
                record.target(),
                message
            ))
        })
        .level_for(env!("CARGO_PKG_NAME"), log_level)
        .level(LevelFilter::Warn)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let log_level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    match setup_logger(log_level) {
        Ok(()) => {},
        Err(e) => {
            eprintln!("Failed to initialize logger: {e}. ");
            exit(1);
        }
    };

    info!("Starting {} version {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

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
                error!("Invalid key {}: {e}", args.key);
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
                error!("Failed to start server: {e}");
                exit(1);
            },
        };
    } else if args.mode == "client" {
        info!("Running in client mode");

        match client::start_client(args).await {
            Ok(()) => {},
            Err(e) => {
                error!("Failed to start client: {e}");
                exit(1);
            },
        };
    } else {
        error!("Available modes: \"server\", \"client\". Got \"{}\"", args.mode);
        exit(1);
    }
}
