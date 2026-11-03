//! Narrow local control adapter. No shell commands or proxy credentials cross this channel.
use serde_json::{json, Value};
use sni_spoof_rs::{
    config::{Config, ListenerConfig},
    proxy::{start_proxy, RunningProxy},
};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("sni-spoof-helper 1 d2956025");
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("--scan") {
        let target: SocketAddr = args.get(2).ok_or("missing target")?.parse()?;
        if target.port() != 443 || !cloudflare(target.ip()) {
            return Err("scanner requires a Cloudflare endpoint on port 443".into());
        }
        if let (Some(iface), Some(index), Some(local)) = (args.get(4), args.get(5), args.get(6)) {
            let local: std::net::IpAddr = local.parse()?;
            std::env::set_var("SNI_SPOOF_INTERFACE", iface);
            std::env::set_var("SNI_SPOOF_INTERFACE_INDEX", index);
            std::env::set_var(
                if local.is_ipv4() {
                    "SNI_SPOOF_LOCAL_V4"
                } else {
                    "SNI_SPOOF_LOCAL_V6"
                },
                local.to_string(),
            );
        }
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async{let mut names=sni_spoof_rs::scan::default_snis();if let Some(last)=args.get(3){if !last.is_empty(){names.retain(|s|s!=last);names.insert(0,last.clone());}}let sem=std::sync::Arc::new(tokio::sync::Semaphore::new(8));let mut jobs=Vec::new();
   for sni in names.into_iter().take(128){let sem=sem.clone();jobs.push(tokio::spawn(async move {let _permit=sem.acquire_owned().await.unwrap();let now=Instant::now();let result=tokio::time::timeout(Duration::from_secs(2),sni_spoof_rs::scan::probe_sni(target,sni.clone(),Duration::from_secs(2))).await;let ok=matches!(result,Ok(ref r) if matches!(r.outcome,sni_spoof_rs::scan::ProbeOutcome::Ok));println!("{}",json!({"sni":sni,"ok":ok,"ms":now.elapsed().as_millis()}));}));}
   for j in jobs{let _=j.await;}
  });
        return Ok(());
    }
    if args.get(1).map(String::as_str) != Some("--broker") {
        return Err("expected --broker session-file".into());
    }
    let logs = std::sync::Arc::new(std::sync::Mutex::new(
        std::collections::VecDeque::<String>::new(),
    ));
    let output = logs.clone();
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || DiagnosticWriter {
            output: output.clone(),
            data: Vec::new(),
        })
        .try_init();
    let text = std::fs::read_to_string(args.get(2).ok_or("missing session")?)?;
    if text.len() > 4096 {
        return Err("invalid session".into());
    }
    let session: Value = serde_json::from_str(&text)?;
    let port = session["port"].as_u64().ok_or("missing port")?;
    let mut stream = TcpStream::connect(("127.0.0.1", u16::try_from(port)?))?;
    writeln!(stream, "{}", json!({"token":session["token"]}))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut running: HashMap<String, RunningProxy> = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.len() > 8192 {
            break;
        }
        let req: Value = serde_json::from_str(&line)?;
        let cmd = req["cmd"].as_str().unwrap_or("");
        let result: Result<Value, String> = (|| match cmd {
            "start" => {
                let id = req["id"].as_str().ok_or("missing id")?.to_string();
                let listen: SocketAddr = req["listen"]
                    .as_str()
                    .ok_or("listen")?
                    .parse()
                    .map_err(|_| "listen")?;
                let connect: SocketAddr = req["connect"]
                    .as_str()
                    .ok_or("connect")?
                    .parse()
                    .map_err(|_| "connect")?;
                if !listen.ip().is_loopback()
                    || connect.ip().is_loopback()
                    || connect.ip().is_unspecified()
                    || connect.port() != 443
                    || listen.port() == 0
                    || !cloudflare(connect.ip())
                {
                    return Err("invalid endpoint".into());
                }
                let iface = req["interface"].as_str().ok_or("interface")?;
                if iface.len() > 128 || iface.contains('\0') {
                    return Err("invalid interface".into());
                }
                std::env::set_var("SNI_SPOOF_INTERFACE", iface);
                std::env::set_var(
                    "SNI_SPOOF_INTERFACE_INDEX",
                    req["interfaceIndex"].as_u64().unwrap_or(0).to_string(),
                );
                if let Some(local) = req["localIp"].as_str() {
                    let local: std::net::IpAddr = local.parse().map_err(|_| "localIp")?;
                    std::env::set_var(
                        if local.is_ipv4() {
                            "SNI_SPOOF_LOCAL_V4"
                        } else {
                            "SNI_SPOOF_LOCAL_V6"
                        },
                        local.to_string(),
                    );
                }
                let fake = req["sni"].as_str().ok_or("sni")?;
                if fake.len() > 219
                    || !fake
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                {
                    return Err("invalid sni".into());
                }
                let cfg = Config {
                    idle_timeout: None,
                    buffer_size: 8,
                    graceful_shutdown_sec: 0,
                    listeners: vec![ListenerConfig {
                        listen,
                        connect,
                        fake_sni: fake.into(),
                        conn_timeout_sec: 5,
                        handshake_timeout_sec: 2,
                        keepalive_time_sec: 11,
                        keepalive_interval_sec: 2,
                    }],
                };
                let proxy = start_proxy(cfg).map_err(|e| e.to_string())?;
                running.insert(id, proxy);
                Ok(json!({"ok":true}))
            }
            "diagnostics" => {
                let lines: Vec<_> = logs
                    .lock()
                    .map_err(|_| "diagnostic buffer unavailable")?
                    .iter()
                    .cloned()
                    .collect();
                Ok(json!({"ok":true,"lines":lines}))
            }
            "stop" => {
                if let Some(id) = req["id"].as_str() {
                    running.remove(id);
                }
                Ok(json!({"ok":true}))
            }
            "shutdown" => {
                running.clear();
                Ok(json!({"ok":true}))
            }
            _ => Err("unknown operation".into()),
        })();
        let response = match result {
            Ok(v) => v,
            Err(e) => json!({"ok":false,"error":e}),
        };
        writeln!(stream, "{response}")?;
        stream.flush()?;
        if cmd == "shutdown" {
            break;
        }
    }
    drop(running);
    Ok(())
}

// Only helper transport diagnostics enter this bounded in-memory buffer.
// Proxy credentials are never sent to this process.
struct DiagnosticWriter {
    output: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    data: Vec<u8>,
}
impl Write for DiagnosticWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.data.extend_from_slice(
            &bytes[..bytes.len().min(4096usize.saturating_sub(self.data.len()))],
        );
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for DiagnosticWriter {
    fn drop(&mut self) {
        if let Ok(mut output) = self.output.lock() {
            if output.len() >= 80 {
                output.pop_front();
            }
            output.push_back(String::from_utf8_lossy(&self.data).trim().to_string());
        }
    }
}

fn cloudflare(ip: std::net::IpAddr) -> bool {
    include_str!("../../data/cloudflare-cidrs.txt")
        .lines()
        .any(|r| {
            let Some((net, bits)) = r.split_once('/') else {
                return false;
            };
            let Ok(net) = net.parse::<std::net::IpAddr>() else {
                return false;
            };
            let Ok(bits) = bits.parse::<u32>() else {
                return false;
            };
            match (ip, net) {
                (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
                    let mask = u32::MAX << (32 - bits);
                    u32::from(a) & mask == u32::from(n) & mask
                }
                (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
                    let mask = u128::MAX << (128 - bits);
                    u128::from(a) & mask == u128::from(n) & mask
                }
                _ => false,
            }
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restrict_destinations() {
        assert!(cloudflare("104.21.56.43".parse().unwrap()));
        assert!(cloudflare("2606:4700::1".parse().unwrap()));
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "91.107.177.38",
            "198.18.0.1",
            "::1",
        ] {
            assert!(!cloudflare(ip.parse().unwrap()));
        }
    }
}
