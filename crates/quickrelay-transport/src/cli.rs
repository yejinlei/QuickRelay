//! Listener options.
//!
//! This module owns *only* the listening-address surface. Full configuration
//! parsing (config files, credential sections, REST endpoints) belongs to
//! `quickrelay-server` and issue YEJ-147; the values here are the ones the
//! transport layer can actually act on, and they are passed around as
//! `ListenerConfig` rather than as `clap` structs so tests can build them
//! directly.

use std::net::{IpAddr, SocketAddr};

/// The datagram size that coturn warns about: a STUN message larger than
/// 1 350 octets is close to the 1 500-byte path MTU and risks fragmentation.
pub const LARGE_PACKET_WARN_BYTES: usize = 1_350;

/// The default TURN/STUN service port.
pub const DEFAULT_TURN_PORT: u16 = 3478;

/// The default per-worker connection ceiling.
pub const DEFAULT_MAX_CONNECTIONS: usize = 65_535;

/// One UDP listening address and the port-space share it wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListeningUdpAddr {
    /// The address to bind, including its port.
    pub addr: SocketAddr,
    /// Port-space share (RFC 6051 §13.1, coturn `--port-share`).
    pub port_share: u32,
}

impl ListeningUdpAddr {
    /// Build a UDP listener entry.
    pub fn new(addr: SocketAddr, port_share: u32) -> Self {
        Self { addr, port_share }
    }
}

/// One TCP listening address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListeningTcpAddr {
    /// The address to bind, including its port.
    pub addr: SocketAddr,
}

/// Errors a listener argument can produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// The argument did not parse as an `ip:port`.
    InvalidAddress(String),
    /// No listening address was configured at all.
    Empty,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::InvalidAddress(s) => write!(f, "invalid listening address `{s}`"),
            CliError::Empty => write!(f, "no listening address configured"),
        }
    }
}

impl std::error::Error for CliError {}

/// Everything the transport layer needs to open its sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerConfig {
    /// UDP listening addresses.
    pub udp: Vec<ListeningUdpAddr>,
    /// TCP listening addresses; empty means no TURN-over-TCP listener.
    pub tcp: Vec<ListeningTcpAddr>,
    /// Worker count. `0` selects the number of logical CPUs.
    pub workers: usize,
    /// UDP `SO_RCVBUF`, in octets. `None` leaves the OS default.
    pub rcvbuf_bytes: Option<usize>,
    /// TCP `SO_RCVBUF`, in octets. `None` leaves the OS default.
    pub tcp_rcvbuf_bytes: Option<usize>,
    /// TCP connection inactivity limit, in seconds.
    pub tcp_idle_timeout_secs: u64,
    /// Datagram size above which a warning is logged.
    pub large_packet_warn_bytes: usize,
    /// Per-worker TCP connection ceiling.
    pub max_connections: usize,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            udp: Vec::new(),
            tcp: Vec::new(),
            workers: 0,
            rcvbuf_bytes: None,
            tcp_rcvbuf_bytes: None,
            tcp_idle_timeout_secs: crate::DEFAULT_IDLE_TIMEOUT_SECS,
            large_packet_warn_bytes: LARGE_PACKET_WARN_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

impl ListenerConfig {
    /// The UDP addresses to bind, in order.
    pub fn udp_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.udp.iter().map(|l| l.addr)
    }

    /// The TCP addresses to bind, in order.
    pub fn tcp_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.tcp.iter().map(|l| l.addr)
    }

    /// Whether any worker is needed at all.
    pub fn is_empty(&self) -> bool {
        self.udp.is_empty() && self.tcp.is_empty()
    }

    /// Parse one `ip:port` argument.
    pub fn parse_address(arg: &str) -> Result<SocketAddr, CliError> {
        let raw = arg
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        raw.parse::<SocketAddr>()
            .map_err(|_| CliError::InvalidAddress(arg.to_string()))
    }

    /// Parse the `--listening-ip` form, pairing each IP with one port.
    ///
    /// A port of `0` means the OS picks one, which is what the tests want.
    pub fn parse_listening_ip(ip: IpAddr, port: u16, port_share: u32) -> ListeningUdpAddr {
        ListeningUdpAddr::new(SocketAddr::new(ip, port), port_share)
    }
}

/// Command-line surface for the listener set.
///
/// Stage 4 (YEJ-147) replaces this with the full `clap`/`toml` parser; until
/// then the `quickrelay` binary composes this with the transport only.
#[derive(Debug, Clone, clap::Parser)]
#[command(about = "QuickRelay STUN/TURN server")]
pub struct Cli {
    /// UDP listen address, repeatable. `0` for the port lets the OS choose.
    #[arg(long, value_parser = ListenerConfig::parse_address, num_args = 1.., default_value = "0.0.0.0:3478")]
    udp: Vec<SocketAddr>,

    /// UDP listening IP, repeatable; pairs with `--listening-port`.
    #[arg(long, value_parser = clap::value_parser!(IpAddr), num_args = 1..)]
    listening_ip: Vec<IpAddr>,

    /// Port for the `--listening-ip` addresses.
    #[arg(long, default_value = "3478")]
    listening_port: u16,

    /// Port-space share for the UDP sockets (RFC 6051 §13.1).
    #[arg(long, default_value = "0")]
    port_share: u32,

    /// TCP listen address, repeatable.
    #[arg(long, value_parser = ListenerConfig::parse_address, num_args = 1..)]
    tcp: Vec<SocketAddr>,

    /// Number of worker threads; `0` selects the logical CPU count.
    #[arg(long, default_value = "0")]
    workers: usize,

    /// UDP receive buffer size in octets.
    #[arg(long)]
    rcvbuf: Option<usize>,

    /// TCP receive buffer size in octets.
    #[arg(long)]
    tcp_rcvbuf: Option<usize>,

    /// TCP connection inactivity limit in seconds.
    #[arg(long, default_value = "90")]
    tcp_idle_timeout: u64,

    /// Warn when a STUN datagram exceeds this many octets.
    #[arg(long, default_value = "1350")]
    large_packet_warn: usize,

    /// Per-worker TCP connection ceiling.
    #[arg(long, default_value = "65535")]
    max_connections: usize,
}

impl Cli {
    /// Collapse the arguments into a transport config.
    pub fn to_config(&self) -> ListenerConfig {
        let udp = if self.listening_ip.is_empty() {
            self.udp
                .iter()
                .map(|a| ListeningUdpAddr::new(*a, self.port_share))
                .collect()
        } else {
            self.listening_ip
                .iter()
                .map(|ip| ListenerConfig::parse_listening_ip(*ip, self.listening_port, self.port_share))
                .collect()
        };
        ListenerConfig {
            udp,
            tcp: self.tcp.iter().map(|a| ListeningTcpAddr { addr: *a }).collect(),
            workers: self.workers,
            rcvbuf_bytes: self.rcvbuf,
            tcp_rcvbuf_bytes: self.tcp_rcvbuf,
            tcp_idle_timeout_secs: self.tcp_idle_timeout,
            large_packet_warn_bytes: self.large_packet_warn,
            max_connections: self.max_connections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_leave_the_os_to_choose() {
        let cfg = ListenerConfig::default();
        assert!(cfg.is_empty());
        assert_eq!(cfg.workers, 0);
        assert_eq!(cfg.rcvbuf_bytes, None);
        assert_eq!(cfg.tcp_idle_timeout_secs, 90);
        assert_eq!(cfg.large_packet_warn_bytes, 1_350);
        assert_eq!(cfg.max_connections, 65_535);
    }

    #[test]
    fn a_bare_ipv4_argument_parses() {
        assert_eq!(
            ListenerConfig::parse_address("0.0.0.0:3478").unwrap(),
            "0.0.0.0:3478".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            ListenerConfig::parse_address("[::]:0").unwrap(),
            "[::]:0".parse::<SocketAddr>().unwrap()
        );
        assert!(ListenerConfig::parse_address("not-an-address").is_err());
        assert!(ListenerConfig::parse_address("").is_err());
    }

    #[test]
    fn listening_ip_pairs_with_its_port() {
        let entry = ListenerConfig::parse_listening_ip(
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            3479,
            4,
        );
        assert_eq!(entry.addr.port(), 3479);
        assert_eq!(entry.port_share, 4);
    }

    #[test]
    fn the_cli_shows_its_listener_flags() {
        let cmd = Cli::command();
        let flags: Vec<String> = cmd
            .get_arguments()
            .map(|a| format!("--{}", a.get_long().unwrap()))
            .collect();
        for expected in [
            "udp",
            "listening-ip",
            "listening-port",
            "port-share",
            "tcp",
            "workers",
            "rcvbuf",
            "tcp-rcvbuf",
            "tcp-idle-timeout",
            "large-packet-warn",
            "max-connections",
        ] {
            assert!(
                flags.iter().any(|f| f == &format!("--{expected}")),
                "missing {expected}: {flags:?}"
            );
        }
    }

    #[test]
    fn parsed_args_become_a_config() {
        let cli = Cli::parse_from([
            "quickrelay",
            "--listening-ip=127.0.0.1",
            "--listening-port=3478",
            "--tcp=127.0.0.1:0",
            "--workers=2",
        ]);
        let cfg = cli.to_config();
        assert_eq!(cfg.udp.len(), 1);
        assert_eq!(cfg.udp[0].addr, "127.0.0.1:3478".parse().unwrap());
        assert_eq!(cfg.tcp.len(), 1);
        assert_eq!(cfg.workers, 2);
    }
}
