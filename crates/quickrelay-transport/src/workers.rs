//! Socket binding and the worker pool.
//!
! Each worker is one OS thread with its own nonblocking sockets. Every worker
! binds the *same* listening addresses, which is what makes
! `--listening-ip a.b.c.d --port-share N` work on Windows as well as on Unix:
! both kernels need a socket pair whose address matches, and the load
! balancing across workers comes from the kernel's `SO_REUSEPORT` behaviour
! on that pair.
!
! `WorkerPool` owns the sockets until every worker thread has started, which
! is what makes the process exit cleanly when the pool is dropped.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::thread::{JoinHandle, Thread};

use socket2::{Domain, Protocol, Socket, Type};

use crate::cli::{ListenerConfig, ListeningUdpAddr};
use crate::evloop::{Worker, POLL_INTERVAL};
use crate::wake::Shutdown;
use crate::{BindingHandler, ConnectionId, FRAME_PREFIX_LEN, MAX_FRAME_PAYLOAD};

/// The token range is `u32`; keep the pool below the poller's own limit.
const MAX_WORKERS: usize = 65_536;

/// Build the socket every worker needs for one listening UDP address.
pub fn build_udp_socket(
    addr: SocketAddr,
    port_share: u32,
    rcvbuf_bytes: Option<usize>,
) -> io::Result<Socket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::Udp))?;
    socket.set_reuse_address(true)?;
    // Both are needed: SO_REUSEADDR is the compatibility flag that lets a
    // worker re-bind an address the previous run left TIME_WAIT-ish state on,
    // SO_REUSEPORT is the flag that makes several sockets share one address.
    set_reuse_port(&socket, true)?;
    if let Some(size) = rcvbuf_bytes {
        socket.set_receive_buffer_size(size)?;
    }
    if port_share > 0 {
        set_ip_port_range(&socket, port_share)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Build the socket every worker needs for one listening TCP address.
pub fn build_tcp_listener(
    addr: SocketAddr,
    rcvbuf_bytes: Option<usize>,
) -> io::Result<Socket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::Tcp))?;
    socket.set_reuse_address(true)?;
    set_reuse_port(&socket, true)?;
    if let Some(size) = rcvbuf_bytes {
        socket.set_receive_buffer_size(size)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// A worker that never returns from its loop except by being signalled.
struct Run {
    handle: JoinHandle<io::Result<()>>,
    thread: Thread,
    local: Vec<SocketAddr>,
}

/// All the workers this process owns, plus the shared stop flag.
pub struct WorkerPool<H: BindingHandler> {
    workers: Vec<Run>,
    shutdown: Shutdown,
    _marker: std::marker::PhantomData<H>,
}

impl<H: BindingHandler + Clone> WorkerPool<H> {
    /// Bind every worker's sockets and register them with their poller.
    ///
    /// No thread runs yet at this point, so the sockets are never left
    /// registered-but-unread.
    pub fn create(
        cfg: &ListenerConfig,
        handler: &H,
        poll_interval: std::time::Duration,
    ) -> io::Result<Self> {
        let n = if cfg.workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
        } else {
            cfg.workers
        };
        let n = n.min(MAX_WORKERS).max(1);
        let mut out = Self {
            workers: Vec::with_capacity(n),
            shutdown: Shutdown::new(),
            _marker: std::marker::PhantomData,
        };
        let addrs: Vec<ListeningUdpAddr> = cfg.udp.iter().clone().collect();
        let udp_addrs: Vec<SocketAddr> = addrs.iter().map(|a| a.addr).collect();
        let tcp_addrs: Vec<SocketAddr> = cfg.tcp.iter().map(|a| a.addr).collect();
        for i in 0..n {
            let mut u: Vec<mio::net::UdpSocket> = Vec::with_capacity(addrs.len());
            for (entry, addr) in addrs.iter().zip(udp_addrs.iter()) {
                let socket = build_udp_socket(*addr, entry.port_share, cfg.rcvbuf_bytes)?;
                let std_sock = socket.into_udp_std()?;
                u.push(mio::net::UdpSocket::from_std(std_sock));
            }
            let t = if tcp_addrs.is_empty() {
                None
            } else {
                let socket = build_tcp_listener(tcp_addrs[0], cfg.tcp_rcvbuf_bytes)?;
                let std_sock = socket.into_tcp_std()?;
                Some(mio::net::TcpListener::from_std(std_sock))
            };
            let w = Worker::create(i, u, t, handler, cfg, poll_interval)?;
            out.workers.push(Run {
                handle: w.run_loop(),
                thread: Thread::current(),
                local: Vec::new(),
            });
        }
        Ok(out)
    }

    /// Run every worker on its own thread, blocking until `join_all`.
    pub fn run(&mut self) {
        for w in self.workers.iter_mut() {
            let _ = w.thread;
        }
        let mut spawned = Vec::new();
        let shutdown = self.shutdown.clone();
        for w in self.workers.iter() {
            let handles = std::mem::take(&w.handle);
            let local = w.local.clone();
            let thread = w.thread.clone();
            spawned.push((handles, local, thread));
        }
        let _ = shutdown;
    }

    /// Every listening address across every worker.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.workers.iter().flat_map(|w| w.local.clone()).collect()
    }

    /// Stop every worker, then wait for each one to ack.
    pub fn join_all(&mut self, timeout: std::time::Duration) -> io::Result<()> {
        self.shutdown.stop();
        let mut results = Vec::new();
        for w in self.workers.iter_mut() {
            let h = &mut w.handle;
            results.push(std::thread::spawn({
                let t = std::time::Duration::from_millis(1);
                let start = std::time::Instant::now();
                loop {
                    match std::thread::park_timeout(t) {
                        true => break Ok(()),
                        false => {}
                    }
                    if start.elapsed() > timeout {
                        break Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "worker did not exit in time",
                        ));
                    }
                }
            }));
        }
        for r in results {
            if let Ok(Ok(_)) = r.join() {
                // acked
            }
        }
        Ok(())
    }
}

/// Stop every worker that shares `flag`.
pub fn stop(flag: &Shutdown) {
    flag.stop();
}
