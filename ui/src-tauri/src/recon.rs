//! Recon réseau natif (mobile) — portage Rust de `engine/app/modules/netrecon.py`.
//!
//! Pur `std::net` + `ureq` (HTTP bloquant), aucun besoin de root. Exposé à l'UI via des
//! commandes Tauri (`invoke`). Sur mobile il n'y a pas de moteur Python : ces commandes
//! remplacent les endpoints `/netrecon/*` du desktop, avec la même logique et les mêmes
//! formes de données.
//!
//! Découverte : TCP « signe de vie » + SSDP/UPnP (identification box/IoT/imprimantes,
//! ce que RED SHIELD voit « au-delà de Fing »). Le DNS inverse et l'audit TLS restent
//! côté desktop en v1 (pas de reverse DNS dans `std`, TLS retiré pour un cross-compile
//! Android fiable).
//!
//! ⚠️ Action ACTIVE (connexions vers la cible) : à n'utiliser que sur cible autorisée.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use serde::Serialize;

const DISCOVERY_PORTS: [u16; 8] = [80, 443, 22, 445, 3389, 8080, 139, 53];
const TOP_PORTS: [u16; 50] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 515, 548, 587, 631,
    993, 995, 1433, 1521, 1723, 2049, 2082, 2083, 3000, 3128, 3306, 3389, 5000, 5060,
    5432, 5900, 5985, 6379, 7547, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9100,
    9200, 27017, 62078, 88,
];
const HTTP_PORTS: [u16; 12] = [80, 8080, 8000, 8008, 8081, 3000, 5000, 8888, 9200, 2082, 3128, 631];
const WORDLIST: [&str; 48] = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin", "dashboard",
    "api", "api/v1", "config", "config.php", ".env", ".git", ".git/config", "backup", "backups",
    "db", "database", "sql", "dump.sql", "test", "dev", "staging", "old", "tmp", "temp",
    "uploads", "files", "images", "assets", "static", "includes", "vendor", "server-status",
    "server-info", "robots.txt", "sitemap.xml", ".htaccess", "web.config", "console",
    "manager", "actuator", "actuator/health", "metrics", "status", "swagger", "graphql", "cgi-bin",
];

#[derive(Serialize, Clone)]
pub struct Host {
    pub ip: String,
    pub hostname: String,
    pub open_ports: Vec<u16>,
    pub device: String,
    pub source: String,
}

#[derive(Serialize, Clone)]
pub struct Port {
    pub port: u16,
    pub proto: String,
    pub service: String,
    pub product: String,
    pub banner: String,
}

#[derive(Serialize, Clone)]
pub struct WebFinding {
    pub path: String,
    pub status: u16,
    pub size: usize,
    pub kind: String,
}

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns", 80 => "http",
        110 => "pop3", 135 => "msrpc", 139 => "netbios", 143 => "imap", 443 => "https",
        445 => "smb", 465 => "smtps", 515 => "printer", 548 => "afp", 587 => "smtp",
        631 => "ipp", 993 => "imaps", 995 => "pop3s", 1433 => "mssql", 1521 => "oracle",
        2049 => "nfs", 3306 => "mysql", 3389 => "rdp", 5432 => "postgres", 5900 => "vnc",
        5985 => "winrm", 6379 => "redis", 7547 => "cwmp", 8080 => "http-alt", 8443 => "https-alt",
        9100 => "jetdirect", 9200 => "elastic", 27017 => "mongodb", _ => "",
    }
}

fn tcp_open(ip: &str, port: u16, ms: u64) -> bool {
    let addr = format!("{ip}:{port}");
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(sa) = addrs.next() {
            return TcpStream::connect_timeout(&sa, Duration::from_millis(ms)).is_ok();
        }
    }
    false
}

fn parse_targets(cidr: &str) -> Vec<String> {
    let c = cidr.trim();
    if let Ok(net) = c.parse::<ipnet::IpNet>() {
        let mut v: Vec<String> = net.hosts().take(512).map(|ip| ip.to_string()).collect();
        if v.is_empty() {
            v.push(net.addr().to_string()); // /32 ou /128
        }
        return v;
    }
    if let Ok(ip) = c.parse::<IpAddr>() {
        return vec![ip.to_string()];
    }
    vec![]
}

fn grab_banner(ip: &str, port: u16) -> (String, String) {
    let addr = format!("{ip}:{port}");
    let sa = match addr.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(s) => s,
        None => return (String::new(), String::new()),
    };
    let mut stream = match TcpStream::connect_timeout(&sa, Duration::from_millis(1200)) {
        Ok(s) => s,
        Err(_) => return (String::new(), String::new()),
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1200)));
    if HTTP_PORTS.contains(&port) {
        let _ = write!(stream, "HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    }
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    let mut product = String::new();
    for line in text.lines() {
        if line.to_lowercase().starts_with("server:") {
            product = line[7..].trim().to_string();
            break;
        }
    }
    (text.chars().take(300).collect(), product)
}

/// SSDP / UPnP (M-SEARCH multicast) → { ip: description serveur }.
/// Identifie box, TV, imprimantes, objets connectés sans root — c'est ce que voit
/// RED SHIELD « au-delà de Fing ». Silencieux si le multicast est indisponible.
fn ssdp_probe(timeout_ms: u64) -> HashMap<String, String> {
    let mut found: HashMap<String, String> = HashMap::new();
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return found,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
               MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    if sock.send_to(msg.as_bytes(), "239.255.255.250:1900").is_err() {
        return found;
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let ip = addr.ip().to_string();
                let text = String::from_utf8_lossy(&buf[..n]);
                let mut desc = String::new();
                for line in text.lines() {
                    if line.to_lowercase().starts_with("server:") {
                        desc = line[7..].trim().to_string();
                    }
                }
                found.entry(ip).or_insert(desc); // premier vu conservé (comme setdefault)
            }
            Err(_) => break, // timeout de lecture → plus de réponse en attente
        }
    }
    found
}

fn ureq_get(url: &str) -> (u16, usize) {
    match ureq::get(url).timeout(Duration::from_secs(4)).call() {
        Ok(r) => {
            let s = r.status();
            let body = r.into_string().unwrap_or_default();
            (s, body.len())
        }
        Err(ureq::Error::Status(code, _)) => (code, 0),
        Err(_) => (0, 0),
    }
}

#[tauri::command]
pub fn discover_hosts(cidr: String) -> Vec<Host> {
    let ips = parse_targets(&cidr);
    if ips.is_empty() {
        return Vec::new();
    }
    // SSDP seulement sur une vraie plage (identification d'équipements du LAN),
    // pas sur une cible unique — comme le moteur Python.
    let ssdp = if ips.len() > 1 {
        ssdp_probe(2000)
    } else {
        HashMap::new()
    };

    let mut alive: Vec<(String, Vec<u16>)> = Vec::new();
    for chunk in ips.chunks(128) {
        let results: Vec<Option<(String, Vec<u16>)>> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|ip| {
                    let ip = ip.clone();
                    s.spawn(move || {
                        let opens: Vec<u16> = DISCOVERY_PORTS
                            .iter()
                            .copied()
                            .filter(|p| tcp_open(&ip, *p, 350))
                            .collect();
                        if opens.is_empty() { None } else { Some((ip, opens)) }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap_or(None)).collect()
        });
        alive.extend(results.into_iter().flatten());
    }

    // Ajoute les hôtes vus en SSDP mais sans port « signe de vie » ouvert
    // (uniquement s'ils font partie de la cible demandée).
    let seen: HashSet<&String> = alive.iter().map(|(ip, _)| ip).collect();
    let in_range: HashSet<&String> = ips.iter().collect();
    let extra: Vec<String> = ssdp
        .keys()
        .filter(|ip| !seen.contains(ip) && in_range.contains(ip))
        .cloned()
        .collect();
    alive.extend(extra.into_iter().map(|ip| (ip, Vec::new())));

    alive.sort_by(|a, b| a.0.cmp(&b.0));
    alive
        .into_iter()
        .map(|(ip, open_ports)| {
            let device = ssdp.get(&ip).cloned().unwrap_or_default();
            let source = if ssdp.contains_key(&ip) { "ssdp" } else { "tcp" };
            Host {
                ip,
                hostname: String::new(),
                open_ports,
                device,
                source: source.into(),
            }
        })
        .collect()
}

#[tauri::command]
pub fn scan_ports(ip: String) -> Vec<Port> {
    let mut open: Vec<u16> = std::thread::scope(|s| {
        let handles: Vec<_> = TOP_PORTS
            .iter()
            .map(|p| {
                let ip = ip.clone();
                let p = *p;
                s.spawn(move || if tcp_open(&ip, p, 400) { Some(p) } else { None })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().unwrap_or(None)).collect()
    });
    open.sort_unstable();
    open.into_iter()
        .map(|p| {
            let (banner, product) = grab_banner(&ip, p);
            Port {
                port: p,
                proto: "tcp".into(),
                service: service_name(p).into(),
                product,
                banner,
            }
        })
        .collect()
}

#[tauri::command]
pub fn web_enum(url: String) -> Vec<WebFinding> {
    let mut base = url.trim().trim_end_matches('/').to_string();
    if !base.starts_with("http") {
        base = format!("http://{base}");
    }
    let (ref_status, _) = ureq_get(&format!("{base}/red-shield-404-probe-zzz"));
    let mut out: Vec<WebFinding> = Vec::new();
    for chunk in WORDLIST.chunks(24) {
        let results: Vec<Option<WebFinding>> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|w| {
                    let base = base.clone();
                    let w = w.to_string();
                    s.spawn(move || {
                        let (status, size) = ureq_get(&format!("{base}/{w}"));
                        if status == 0
                            || status == 404
                            || (ref_status != 0 && ref_status != 404 && status == ref_status)
                        {
                            None
                        } else {
                            Some(WebFinding {
                                path: format!("/{w}"),
                                status,
                                size,
                                kind: "dir".into(),
                            })
                        }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap_or(None)).collect()
        });
        out.extend(results.into_iter().flatten());
    }
    out.sort_by(|a, b| (a.status, &a.path).cmp(&(b.status, &b.path)));
    out.truncate(200);
    out
}
