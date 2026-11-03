use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::packet::tls;

pub const DEFAULT_SNIS: &str = include_str!("../data/scan-snis.txt");
pub const DEFAULT_TARGET: &str = "104.18.4.130:443";
pub const DEFAULT_TIMEOUT_SECS: u64 = 6;
pub const DEFAULT_CONCURRENCY: usize = 10;

pub struct ScanOpts {
    pub target: SocketAddr,
    pub timeout: Duration,
    pub concurrency: usize,
    pub snis: Vec<String>,
    pub output: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ProbeOutcome {
    Ok,
    ConnectFailed(String),
    ConnectTimeout,
    HandshakeFailed(String),
    ReadTimeout,
    BadResponse(u8),
    EmptyResponse,
}

impl std::fmt::Display for ProbeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeOutcome::Ok => write!(f, "ok"),
            ProbeOutcome::ConnectFailed(e) => write!(f, "connect failed: {}", e),
            ProbeOutcome::ConnectTimeout => write!(f, "connect timeout"),
            ProbeOutcome::HandshakeFailed(e) => write!(f, "handshake failed: {}", e),
            ProbeOutcome::ReadTimeout => write!(f, "read timeout"),
            ProbeOutcome::BadResponse(b) => write!(f, "bad response: 0x{b:02x}"),
            ProbeOutcome::EmptyResponse => write!(f, "empty response"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub sni: String,
    pub outcome: ProbeOutcome,
}

pub fn run(args: &[String]) {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {}", e);
            eprintln!();
            print_help();
            std::process::exit(2);
        }
    };

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let _ = scan_all(opts).await;
    });
}

fn parse_args(args: &[String]) -> Result<ScanOpts, String> {
    let mut target: Option<SocketAddr> = None;
    let mut timeout_secs: u64 = DEFAULT_TIMEOUT_SECS;
    let mut concurrency: usize = DEFAULT_CONCURRENCY;
    let mut list_path: Option<String> = None;
    let mut output: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--target" | "-t" => {
                i += 1;
                let v = args.get(i).ok_or("missing value for --target")?;
                target = Some(
                    v.parse()
                        .map_err(|e| format!("invalid --target '{}': {}", v, e))?,
                );
            }
            "--timeout" => {
                i += 1;
                let v = args.get(i).ok_or("missing value for --timeout")?;
                timeout_secs = v
                    .parse()
                    .map_err(|e| format!("invalid --timeout '{}': {}", v, e))?;
            }
            "--concurrency" | "-c" => {
                i += 1;
                let v = args.get(i).ok_or("missing value for --concurrency")?;
                concurrency = v
                    .parse()
                    .map_err(|e| format!("invalid --concurrency '{}': {}", v, e))?;
                if concurrency == 0 {
                    return Err("--concurrency must be >= 1".into());
                }
            }
            "--list" | "-l" => {
                i += 1;
                list_path = Some(args.get(i).ok_or("missing value for --list")?.clone());
            }
            "--output" | "-o" => {
                i += 1;
                output = Some(args.get(i).ok_or("missing value for --output")?.clone());
            }
            other => {
                return Err(format!("unknown argument: {}", other));
            }
        }
        i += 1;
    }

    let snis = if let Some(path) = list_path {
        let content = std::fs::read_to_string(Path::new(&path))
            .map_err(|e| format!("failed to read list '{}': {}", path, e))?;
        parse_sni_list(&content)
    } else {
        parse_sni_list(DEFAULT_SNIS)
    };

    if snis.is_empty() {
        return Err("SNI list is empty".into());
    }

    Ok(ScanOpts {
        target: target.unwrap_or_else(|| DEFAULT_TARGET.parse().unwrap()),
        timeout: Duration::from_secs(timeout_secs),
        concurrency,
        snis,
        output,
    })
}

pub fn default_snis() -> Vec<String> {
    parse_sni_list(DEFAULT_SNIS)
}

pub fn parse_sni_list(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

fn print_help() {
    eprintln!("sni-spoof-rs scan -- probe which SNIs pass DPI as fake_sni candidates");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  sni-spoof-rs scan [OPTIONS]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!(
        "  -t, --target ADDR        Cloudflare IP:port to probe against (default: {})",
        DEFAULT_TARGET
    );
    eprintln!(
        "      --timeout SECS       per-probe timeout in seconds (default: {})",
        DEFAULT_TIMEOUT_SECS
    );
    eprintln!(
        "  -c, --concurrency N      parallel probes (default: {})",
        DEFAULT_CONCURRENCY
    );
    eprintln!("  -l, --list FILE          custom SNI list file (one per line, # for comments)");
    eprintln!("  -o, --output FILE        write working SNIs to file (one per line)");
    eprintln!("  -h, --help               print this help");
    eprintln!();
    eprintln!("Working SNIs are printed to stdout; progress/diagnostics go to stderr.");
    eprintln!("Example: sni-spoof-rs scan -o working.txt");
}

pub async fn scan_all(opts: ScanOpts) -> Vec<ProbeResult> {
    eprintln!(
        "scanning {} SNIs against {} (concurrency={}, timeout={}s)",
        opts.snis.len(),
        opts.target,
        opts.concurrency,
        opts.timeout.as_secs(),
    );
    eprintln!();

    let sem = Arc::new(Semaphore::new(opts.concurrency));
    let target = opts.target;
    let timeout = opts.timeout;
    let total = opts.snis.len();

    let mut handles = Vec::with_capacity(total);
    for sni in opts.snis {
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore closed");
            probe_sni(target, sni, timeout).await
        }));
    }

    let mut results: Vec<ProbeResult> = Vec::with_capacity(total);
    let mut done = 0usize;
    let mut ok = 0usize;
    for h in handles {
        match h.await {
            Ok(r) => {
                done += 1;
                if matches!(r.outcome, ProbeOutcome::Ok) {
                    ok += 1;
                    println!("{}", r.sni);
                }
                if done.is_multiple_of(20) || done == total {
                    eprintln!("  progress: {}/{} ({} ok)", done, total, ok);
                }
                results.push(r);
            }
            Err(e) => {
                eprintln!("task panic: {}", e);
            }
        }
    }

    eprintln!();
    eprintln!("=== summary ===");
    eprintln!("total:     {}", total);
    eprintln!("ok:        {}", ok);
    eprintln!("failed:    {}", total - ok);

    if let Some(path) = opts.output {
        let working: Vec<&str> = results
            .iter()
            .filter(|r| matches!(r.outcome, ProbeOutcome::Ok))
            .map(|r| r.sni.as_str())
            .collect();
        let body = working.join("\n") + "\n";
        if let Err(e) = std::fs::write(&path, body) {
            eprintln!("failed to write {}: {}", path, e);
            std::process::exit(1);
        }
        eprintln!("wrote {} working SNIs to {}", working.len(), path);
    }

    results
}

pub async fn probe_sni(target: SocketAddr, sni: String, timeout: Duration) -> ProbeResult {
    if sni.len() > 219 {
        return ProbeResult {
            sni,
            outcome: ProbeOutcome::HandshakeFailed("sni too long".into()),
        };
    }

    let connect = async {
        // CLI callers without a physical binding retain upstream behavior.
        if std::env::var("SNI_SPOOF_INTERFACE").is_err() {
            return TcpStream::connect(target).await;
        }
        let sock = socket2::Socket::new(
            if target.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        crate::handler::bind_physical_interface(&sock, target.is_ipv4())?;
        let name = if target.is_ipv4() {
            "SNI_SPOOF_LOCAL_V4"
        } else {
            "SNI_SPOOF_LOCAL_V6"
        };
        let local = std::env::var(name)
            .map_err(std::io::Error::other)?
            .parse::<std::net::IpAddr>()
            .map_err(std::io::Error::other)?;
        sock.bind(&SocketAddr::new(local, 0).into())?;
        sock.set_nonblocking(true)?;
        match sock.connect(&target.into()) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            #[cfg(unix)]
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => (),
            Err(e) => return Err(e),
        }
        let stream = TcpStream::from_std(sock.into())?;
        stream.writable().await?;
        if let Some(e) = stream.take_error()? {
            return Err(e);
        }
        Ok(stream)
    };
    let mut stream = match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return ProbeResult {
                sni,
                outcome: ProbeOutcome::ConnectFailed(e.to_string()),
            }
        }
        Err(_) => {
            return ProbeResult {
                sni,
                outcome: ProbeOutcome::ConnectTimeout,
            }
        }
    };

    let ch = tls::build_client_hello(&sni);
    match tokio::time::timeout(timeout, stream.write_all(&ch)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return ProbeResult {
                sni,
                outcome: ProbeOutcome::HandshakeFailed(e.to_string()),
            }
        }
        Err(_) => {
            return ProbeResult {
                sni,
                outcome: ProbeOutcome::HandshakeFailed("write timeout".into()),
            }
        }
    }

    let mut buf = [0u8; 5];
    match tokio::time::timeout(timeout, stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            if buf[0] == 0x16 {
                ProbeResult {
                    sni,
                    outcome: ProbeOutcome::Ok,
                }
            } else {
                ProbeResult {
                    sni,
                    outcome: ProbeOutcome::BadResponse(buf[0]),
                }
            }
        }
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ProbeResult {
                    sni,
                    outcome: ProbeOutcome::EmptyResponse,
                }
            } else {
                ProbeResult {
                    sni,
                    outcome: ProbeOutcome::HandshakeFailed(e.to_string()),
                }
            }
        }
        Err(_) => ProbeResult {
            sni,
            outcome: ProbeOutcome::ReadTimeout,
        },
    }
}
