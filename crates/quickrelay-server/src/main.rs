use std::io::{self, IsTerminal, Read};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use clap::Parser;
use mio::event::Events;
use quickrelay_transport::worker::{Worker, WorkerConfig, WorkerWake, EVENT_CAPACITY};

use quickrelay_binding as binding;
use quickrelay_server::binding_chain;

/// The control latch. The main thread raises it, every worker waits on it.
struct ShutdownLatch {
    cv: Condvar,
}

impl ShutdownLatch {
    fn new() -> (Arc<Self>, Arc<Mutex<bool>>) {
        (Arc::new(Self { cv: Condvar::new() }), Arc::new(Mutex::new(false)))
    }

    /// Wait until `stopped` is raised, or `until` elapses.
    fn wait(&self, stopped: &Arc<Mutex<bool>>, until: Option<Duration>) {
        let mut stopped = stopped.lock().unwrap();
        loop {
            if *stopped {
                return;
            }
            let Some(deadline) = until.map(|u| Instant::now() + u) else {
                stopped = self.cv.wait_while(stopped, |stopped| !*stopped).unwrap();
                continue;
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            let (guard, outcome) =
                self.cv.wait_timeout_while(stopped, remaining, |stopped| !*stopped).unwrap();
            stopped = guard;
            if outcome.timed_out() {
                return;
            }
        }
    }

    /// Raise the latch and release every waiting worker.
    fn stop(&self, stopped: &Arc<Mutex<bool>>) {
        *stopped.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

/// A worker thread, and the wake handle that ends it.
struct RunningWorker {
    handle: JoinHandle<()>,
    wake: WorkerWake,
}

/// Read one line from stdin — or detect that stdin is already closed — and
/// raise the latch. This is the zero-dependency control channel: Stage 4 swaps
/// it for a signal handler, which needs a crate this workspace does not vendor.
fn install_stdin_listener(latch: Arc<ShutdownLatch>, stopped: Arc<Mutex<bool>>) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut line = String::new();
        match io::stdin().lock().read_to_string(&mut line) {
            Ok(_) if line.trim().is_empty() => tracing::info!("stdin closed; stopping"),
            Ok(_) => tracing::info!("control line on stdin: {}", line.trim()),
            Err(e) => tracing::warn!("stdin closed by an error: {e}"),
        }
        latch.stop(&stopped);
    })
}

/// QuickRelay: a high-performance STUN/TURN server for WebRTC.
#[derive(Debug, Parser)]
#[command(
    name = "quickrelay",
    version,
    long_about = "QuickRelay is a high-performance STUN/TURN server for WebRTC.

UDP datagrams are sharded across workers behind one SO_REUSEPORT listening
address. A TCP listener accepts TURN-over-TCP control connections on the same
port, using the 16-bit big-endian length prefix that ICE-TCP already speaks
(RFC 6062 Section 11.15, RFC 4571 Section 2).

Send EOF or any line on stdin to stop; every worker then closes its sockets
and exits. RUST_LOG controls log level."
)]
struct Cli {
    /// Listening addresses. Repeat to bind several addresses at once.
    #[arg(
        long,
        value_name = "ADDRESS",
        action = clap::ArgAction::Append,
        default_value = "0.0.0.0",
        value_parser = parse_address,
    )]
    listening_ip: Vec<IpAddr>,

    /// The port every listening address binds. 0 lets the system choose one.
    #[arg(long, value_name = "PORT", default_value_t = 3478)]
    listening_port: u16,

    /// How many workers to start, one per listening address.
    #[arg(long, value_name = "N", default_value_t = 1)]
    workers: usize,

    /// Per-worker UDP receive buffer in octets. 0 leaves the system default.
    #[arg(long, value_name = "OCTETS", default_value_t = 4 * 1024 * 1024)]
    udp_rbuf_size: usize,

    /// Stop after this many seconds. For smoke tests and load harnesses.
    #[arg(long, value_name = "SECONDS")]
    shutdown_after: Option<u64>,

    /// Always watch stdin for a stop request, even when stdin is not a
    /// terminal. Off by default: a scheduler that leaves stdin closed would
    /// otherwise stop the server the moment it starts.
    #[arg(long, default_value_t = false)]
    control_stdin: bool,
}

/// `0.0.0.0` and `[::]` are the two wildcards; anything else must already be
/// an address the resolver accepted.
fn parse_address(value: &str) -> Result<IpAddr, String> {
    value.parse().map_err(|e: std::net::AddrParseError| e.to_string())
}

/// The address list a CHANGE-REQUEST is resolved against: the configured
/// listeners, minus the placeholders the kernel replaces for us.
///
/// A wildcard IP and port `0` are not addresses any reply leaves from, so they
/// cannot satisfy or block a flag — the identities of the sockets they became
/// are added when the worker binds, through `set_udp` and `set_tcp_identity`.
fn listen_identities(listeners: &[SocketAddr]) -> Vec<binding::ServerIdentity> {
    let mut out: Vec<binding::ServerIdentity> = Vec::new();
    for address in listeners {
        if matches!(address.ip(), IpAddr::V4(v4) if v4.is_unspecified())
            || matches!(address.ip(), IpAddr::V6(v6) if v6.is_unspecified())
            || address.port() == 0
        {
            continue;
        }
        let identity = binding_chain::identity_of_socket(*address);
        if !out.contains(&identity) {
            out.push(identity);
        }
    }
    out
}

/// Whether stdin should be read as a stop request. A terminal implies an
/// operator who is watching; anything else needs an explicit opt-in.
fn stdin_control_is_live(control_stdin: bool) -> bool {
    control_stdin || std::io::stdin().is_terminal()
}

/// Start one worker: bind its sockets, give the handler a sender for replies,
/// and hand the worker to its own thread.
fn start_worker(
    index: usize,
    count: usize,
    listening: SocketAddr,
    listeners: &[SocketAddr],
    rcvbuf: usize,
) -> std::io::Result<Option<RunningWorker>> {
    let config = WorkerConfig {
        index,
        count,
        udp_addr: Some(listening),
        udp_rcvbuf: rcvbuf,
        tcp_addr: Some(listening),
        ..WorkerConfig::default()
    };
    let mut handler = binding_chain::BindingHandler::new();
    // The configured listen list, minus the placeholders the kernel
    // substitutes: a CHANGE-REQUEST is resolved against every address the
    // process binds, so a flag the one socket cannot honor is still answerable
    // when another listener can. The sockets the placeholders became join the
    // list when they are bound.
    let addresses = listen_identities(listeners);
    handler.set_addresses(addresses);
    let (mut worker, wake) = Worker::new(config, handler)?;

    // Bind the datagram socket, then give the handler a sender bound to the
    // address the socket actually landed on. With port 0 that is the only way
    // the reply leaves the same port the request came in on, which is what
    // MAPPED-ADDRESS has to claim.
    let udp_addr = if worker.new_udp(listening, rcvbuf).is_ok() {
        worker.udp_local_addr()
    } else {
        tracing::warn!("worker {index}: datagram socket did not bind {listening}");
        None
    };
    if let Some(udp) = udp_addr {
        match binding_chain::reply_socket(udp) {
            Ok(sender) => worker.handler_mut().set_udp(sender),
            Err(e) => tracing::warn!(
                "worker {index}: no reply sender on {udp}: {e}; datagrams will be dropped"
            ),
        }
    }
    let tcp_addr = if worker.new_tcp(listening).is_ok() {
        let tcp = worker.listener_local_addr();
        if let Some(tcp) = tcp {
            // A control-connection reply leaves from the listener, not from
            // the datagram socket, so the identity must match that address.
            worker.handler_mut()
                .set_tcp_identity(binding_chain::identity_of_socket(tcp));
        }
        tcp
    } else {
        tracing::warn!("worker {index}: control listener did not bind {listening}; UDP only");
        None
    };

    if udp_addr.is_none() && tcp_addr.is_none() {
        // Both paths failed: the worker has nothing to serve.
        return Ok(None);
    }

    let handle = thread::Builder::new()
        .name(format!("quickrelay-worker-{index}"))
        .spawn(move || {
            let events = &mut Events::with_capacity(EVENT_CAPACITY);
            let stats = worker.run(events);
            tracing::info!(
                udp = %udp_addr.map(|a| a.to_string()).unwrap_or_default(),
                tcp = %tcp_addr.map(|a| a.to_string()).unwrap_or_default(),
                udp_packets = stats.udp_packets,
                accepts = stats.accepts,
                dropped = stats.dropped,
                tcp_packets = stats.tcp_packets,
                "worker {index} stopped"
            );
        })?;

    Ok(Some(RunningWorker { handle, wake }))
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let listeners = cli
        .listening_ip
        .iter()
        .map(|ip| SocketAddr::new(*ip, cli.listening_port))
        .collect::<Vec<_>>();

    if listeners.is_empty() || cli.workers == 0 {
        return Err(
            "at least one listening address and one worker are required".to_owned(),
        );
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let mut running = Vec::new();
    for index in 0..cli.workers {
        let listening = listeners[index % listeners.len()];
        match start_worker(index, cli.workers, listening, &listeners, cli.udp_rbuf_size)
            .map_err(|e| format!("failed to start worker {index}: {e}"))?
        {
            Some(worker) => running.push(worker),
            None => tracing::warn!("worker {index} at {listening} bound nothing; skipped"),
        }
    }

    if running.is_empty() {
        return Err("no worker could bind a listening address".to_owned());
    }

    let (latch, stopped) = ShutdownLatch::new();
    let mut stdin: Option<JoinHandle<()>> = None;
    let listening = listeners
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if stdin_control_is_live(cli.control_stdin) {
        stdin = Some(install_stdin_listener(
            Arc::clone(&latch),
            Arc::clone(&stopped),
        ));
        tracing::info!(
            workers = running.len(),
            %listening,
            "quickrelay is up; send EOF or any line on stdin to stop"
        );
    } else {
        // Stdin is not a control channel here: it is not a terminal and
        // --control-stdin was not given. A scheduler leaves stdin closed,
        // which would otherwise end the process the instant it starts.
        tracing::info!(
            workers = running.len(),
            %listening,
            "quickrelay is up; stdin is not a control channel (not a terminal; \
             pass --control-stdin to enable it)"
        );
    }

    latch.wait(&stopped, cli.shutdown_after.map(Duration::from_secs));
    for worker in &running {
        worker.wake.wake();
    }

    // Join the workers so the process cannot exit while a worker still owns
    // sockets. Each worker logs its own stats; joining only reaps the thread.
    for worker in running {
        let _ = worker.handle.join();
    }
    if let Some(stdin) = stdin {
        let _ = stdin.join();
    }
    tracing::info!("quickrelay stopped");
    Ok(())
}
