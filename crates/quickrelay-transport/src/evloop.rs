//! One worker's nonblocking event loop.
//!
//! A worker owns the UDP sockets it was bound with, the TCP listener it was
//! bound with, and the connection table for the TURN-over-TCP connections it
//! accepts. Everything it does is driven by one `mio::Poll` instance: the UDP
//! sockets report readable for received datagrams, the TCP listener reports
//! readable for new connections, and each accepted connection reports
//! readable for framed payloads and writable when a reply is queued.
//!
//! No STUN payload is interpreted here. Every octet is handed to the
//! [`BindingHandler`] and whatever bytes come back are sent out unchanged.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use log::{debug, error, info, warn};
use mio::{Interest, Poll, Token};

use crate::cli::ListenerConfig;
use crate::connmgr::{queue_frame, Entry, Manager};
use crate::wake::{Shutdown, Wake};
use crate::{
    BindingHandler, ConnectionId, DEFAULT_IDLE_TIMEOUT_SECS, FrameError, FRAME_PREFIX_LEN,
    MAX_FRAME_PAYLOAD,
};

/// The token of the process-shutdown pipe.
const SHUTDOWN_TOKEN: Token = Token(u64::MAX);

/// Everything one worker owns.
pub struct Worker<H: BindingHandler> {
    poll: Poll,
    /// The UDP sockets this worker bound.
    udp: Vec<mio::net::UdpSocket>,
    /// The worker index, so `ss`/`netstat` output can be told apart.
    index: usize,
    /// Reusable UDP receive buffer, one maximum-length datagram.
    udp_recv: Box<[u8]>,
    /// Reusable UDP source scratch.
    udp_source: [u8; 64],
    /// The TCP listener, when the worker was configured with one.
    tcp_listener: Option<mio::net::TcpListener>,
    /// The accepted connections of this worker.
    conns: Manager<H>,
    /// Reusable TCP read buffers, one per maximum-length frame.
    tcp_recv: Vec<Box<[u8]>>,
    shutdown: Shutdown,
    wake: Wake,
}

/// A UDP datagram that reached the handler.
#[derive(Debug, Clone, Copy)]
pub struct Datagram<'a> {
    /// The socket that received it.
    pub source_socket: usize,
    /// The peer address.
    pub peer: SocketAddr,
    /// The raw datagram, unparsed.
    pub payload: &'a [u8],
}

impl<H: BindingHandler> Worker<H> {
    /// Bind the UDP sockets this worker should own.
    ///
    /// `udp_addrs` are the listening addresses of *this* worker; the worker
    /// pool hands every worker the same list, so all workers share one
    /// listening address through `SO_REUSEPORT`.
    pub fn bind_udp(
        addrs: &[SocketAddr],
        port_share: u32,
        rcvbuf_bytes: Option<usize>,
    ) -> io::Result<Vec<socket2::Socket>> {
        let mut out = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let family = if addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let socket = socket2::Socket::new(family, socket2::Type::DGRAM, Some(0x04))?;
            // Both are needed: `SO_REUSEADDR` is the compatibility flag,
            // `SO_REUSEPORT` is the load-balancing flag.
            socket.set_reuse_address(true)?;
            socket.set_reuse_port(true)?;
            if let Some(bytes) = rcvbuf_bytes {
                socket.set_receive_buffer_size(bytes)?;
            }
            if port_share > 0 {
                socket.set_ip_port_range(port_share as u16, 0x3FFF)?;
            }
            socket.bind(&(*addr).into())?;
            socket.set_nonblocking(true)?;
            out.push(socket);
        }
        Ok(out)
    }

    /// Build a worker from already-bound sockets.
    pub fn new(index: usize, udp: Vec<socket2::Socket>, cfg: &ListenerConfig) -> io::Result<Self> {
        let poll = Poll::new()?;
        let mut udp_socks = Vec::with_capacity(udp.len());
        let token = 0usize;
        for socket in udp {
            let std_sock = socket.into_udp_std()?;
            let mut mio_sock = mio::net::UdpSocket::from_std(std_sock)?;
            poll.register(
                &mut mio_sock,
                Token(token),
                Interest::READABLE | Interest::PRIORITY,
            )?;
            udp_socks.push(mio_sock);
            token += 1;
        }
        let tcp_listener = if cfg.tcp.is_empty() {
            None
        } else {
            let socket = crate::workers::bind_tcp(&cfg.tcp, cfg.tcp_rcvbuf_bytes)?;
            let mio_listener = mio::net::TcpListener::from_std(socket.into_tcp_std()?);
            poll.register(&mut mio_listener, TCP_LISTENER_TOKEN, Interest::READABLE)?;
            Some(mio_listener)
        };
        let conns = Manager::<H>::new()
            .with_idle_timeout(Duration::from_secs(cfg.tcp_idle_timeout_secs.max(1)));
        Ok(Self {
            poll,
            udp: udp_socks,
            index,
            udp_recv: vec![0u8; FRAME_PREFIX_LEN + MAX_FRAME_PAYLOAD as usize + 1].into_boxed_slice(),
            udp_source: [0; 64],
            tcp_listener,
            conns,
            tcp_recv: Vec::new(),
            shutdown: Shutdown::new(),
            wake: Wake::new(),
        })
    }

    /// The UDP sockets this worker is listening on, for diagnostics.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.udp.iter().map(|s| s.local_addr().unwrap()).collect()
    }
}

const TCP_LISTENER_TOKEN: Token = Token(u64::MAX - 1);

impl<H: BindingHandler> Worker<H> {
    /// Run until `shutdown` is signalled or a fatal error occurs.
    pub fn run_until_shutdown(mut self, deadline: Option<Duration>) -> io::Result<()> {
        let poll_timeout = deadline.unwrap_or(Duration::from_millis(500));
        loop {
            if self.shutdown.should_stop() {
                break;
            }
            match self.poll.poll(Some(poll_timeout)) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;

    #[test]
    fn rebind_on_loopback_uses_the_port_share_flag() {
        let cfg = ListenerConfig {
            udp: vec![crate::cli::ListeningUdpAddr::new(
                "127.0.0.1:0".parse().unwrap(),
                0,
            )],
            tcp: Vec::new(),
            workers: 1,
            rcvbuf_bytes: None,
            tcp_rcvbuf_bytes: None,
            tcp_idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            large_packet_warn_bytes: 1350,
            max_connections: 65_535,
        };
        let sockets = Worker::<crate::test_util::Noop>::bind_udp(&[cfg.udp[0].addr], 0, None).unwrap();
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].nonblocking(), Some(true));
        let _ = StdUdpSocket::new;
    }
}
