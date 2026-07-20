// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Concurrent UDP receive benchmark for `UdpBatchReceiver` on a Linux `veth` pair.
//!
//! The benchmark re-execs itself inside a private user and network namespace,
//! creates a `veth` pair, and binds sender and receiver sockets to opposite ends
//! of that link. A sender thread continuously blasts a fixed burst of UDP packets
//! to create receive-side socket lock contention while the receiver runs on a
//! multithreaded Tokio runtime.
//!
//! Each received packet performs a tiny busy-loop to mimic per-packet
//! processing. This keeps the receiver from draining the socket immediately so
//! the batched path has an opportunity to accumulate packets in the kernel queue.
//!
//! The benchmark compares two receive strategies:
//! - `single`: one packet per receive syscall
//! - `batched`: a `UdpBatchReceiver` instantiated with a fixed receive batch size
//!
//! The sender always transmits bursts of 64 packets. The benchmark runs one
//! `single` baseline and then `batched` with receive batch sizes of 16, 32, and
//! 64, reporting both throughput and relative throughput gain over `single`.

#![allow(missing_docs)]

use std::{
    env, io,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    process::{Command, ExitStatus},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use ana_gotatun::packet::PacketBufPool;
use snap_tun::udp_batch::{RecvBatchError, UdpBatchReceiver};
use socket2::SockRef;
use tokio::{net::UdpSocket, runtime::Runtime, time};

const BENCH_PACKET_SIZE: usize = 1024;
const SENDER_BURST_SIZE: usize = 64;
const BATCH_SIZES: [usize; 3] = [16, 32, 64];
const WARMUP_SAMPLES: usize = 2;
const MEASURE_SAMPLES: usize = 10;
const WORK_US: u64 = 1;
const DURATION_MS: u64 = 2000;
const RECV_TIMEOUT_MS: u64 = 250;
const SOCKET_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const UDP_BATCH_VETH_NAMESPACE_ENV: &str = "UDP_BATCH_VETH_NAMESPACE";
const VETH_LEFT_NAME: &str = "udpbatch0";
const VETH_RIGHT_NAME: &str = "udpbatch1";
const VETH_LEFT_IP: &str = "10.231.0.1";
const VETH_RIGHT_IP: &str = "10.231.0.2";

#[derive(Debug)]
enum BenchmarkVariant {
    Single,
    Batched,
}

impl std::fmt::Display for BenchmarkVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchmarkVariant::Single => write!(f, "single"),
            BenchmarkVariant::Batched => write!(f, "batched"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BenchEndpoints {
    sender_bind: SocketAddr,
    receiver_bind: SocketAddr,
}

#[derive(Clone, Copy)]
struct BenchStats {
    packets: usize,
    loop_iterations: usize,
    bytes: usize,
}

#[derive(Clone, Copy)]
struct BenchRun {
    stats: BenchStats,
    receive_duration: Duration,
}

#[derive(Clone, Copy)]
struct Summary {
    run: BenchRun,
    throughput_mib_s: f64,
}

struct BurstSender {
    socket: StdUdpSocket,
}

struct NonBatchedScenario {
    sender: BurstSender,
    receiver: UdpSocket,
    pool: PacketBufPool<BENCH_PACKET_SIZE>,
}

struct BatchedScenario<const BATCH_SIZE: usize> {
    sender: BurstSender,
    receiver_socket: UdpSocket,
    receiver: UdpBatchReceiver<BATCH_SIZE, BENCH_PACKET_SIZE>,
    pool: PacketBufPool<BENCH_PACKET_SIZE>,
}

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("create benchmark runtime")
    })
}

fn burst_payloads(burst_size: usize) -> Vec<Vec<u8>> {
    (0..burst_size)
        .map(|packet_index| {
            (0..BENCH_PACKET_SIZE)
                .map(|byte_index| ((packet_index + byte_index) & 0xff) as u8)
                .collect::<Vec<_>>()
        })
        .collect()
}

impl BurstSender {
    fn new(bind_addr: SocketAddr, target: SocketAddr) -> io::Result<Self> {
        let socket = StdUdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        SockRef::from(&socket).set_send_buffer_size(SOCKET_BUFFER_BYTES)?;
        socket.connect(target)?;
        Ok(Self { socket })
    }

    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    fn send_burst_forever(&self, burst: &[Vec<u8>], running: &AtomicBool) -> io::Result<()> {
        while running.load(Ordering::Relaxed) {
            for payload in burst {
                loop {
                    match self.socket.send(payload) {
                        Ok(_) => break,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if !running.load(Ordering::Relaxed) {
                                return Ok(());
                            }
                            std::hint::spin_loop();
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Ok(())
    }
}

fn spawn_sender(
    sender: &BurstSender,
    burst: &[Vec<u8>],
    running: &Arc<AtomicBool>,
) -> io::Result<JoinHandle<io::Result<()>>> {
    let sender = sender.try_clone()?;
    let sender_running = Arc::clone(running);
    let sender_burst = burst.to_vec();
    Ok(std::thread::spawn(move || {
        sender.send_burst_forever(&sender_burst, &sender_running)
    }))
}

fn finish_sender(
    running: &AtomicBool,
    sender_thread: JoinHandle<io::Result<()>>,
) -> io::Result<()> {
    running.store(false, Ordering::Relaxed);
    sender_thread
        .join()
        .map_err(|_| io::Error::other("sender thread panicked"))?
}

impl NonBatchedScenario {
    async fn new() -> io::Result<Self> {
        let endpoints = veth_endpoints();
        let receiver = bind_receiver_socket(endpoints.receiver_bind)?;
        let sender = BurstSender::new(endpoints.sender_bind, receiver.local_addr()?)?;
        Ok(Self {
            sender,
            receiver,
            pool: PacketBufPool::new(1),
        })
    }

    async fn run(&mut self, burst: &[Vec<u8>], duration: Duration) -> io::Result<BenchRun> {
        let running = Arc::new(AtomicBool::new(true));
        let sender_thread = spawn_sender(&self.sender, burst, &running)?;

        let mut bytes = 0usize;
        let mut loop_iterations = 0usize;
        let mut packets = 0usize;
        let start = Instant::now();

        while start.elapsed() < duration {
            let mut packet = self.pool.get();
            let (size, _from) =
                time::timeout(recv_timeout(), self.receiver.recv_from(packet.as_mut()))
                    .await
                    .map_err(|_| {
                        io::Error::other(
                            "non-batched receiver timed out during concurrent benchmark",
                        )
                    })??;
            packets += 1;
            bytes += size;
            loop_iterations += 1;
            simulate_packet_processing();
        }

        finish_sender(&running, sender_thread)?;

        Ok(BenchRun {
            stats: BenchStats {
                packets,
                loop_iterations,
                bytes,
            },
            receive_duration: start.elapsed(),
        })
    }
}

impl<const BATCH_SIZE: usize> BatchedScenario<BATCH_SIZE> {
    async fn new() -> io::Result<Self> {
        let endpoints = veth_endpoints();
        let receiver_socket = bind_receiver_socket(endpoints.receiver_bind)?;
        let sender = BurstSender::new(endpoints.sender_bind, receiver_socket.local_addr()?)?;
        let pool = PacketBufPool::new(BATCH_SIZE);
        let receiver =
            UdpBatchReceiver::<BATCH_SIZE, BENCH_PACKET_SIZE>::new(&receiver_socket, &pool)?;
        Ok(Self {
            sender,
            receiver_socket,
            receiver,
            pool,
        })
    }

    async fn run(&mut self, burst: &[Vec<u8>], duration: Duration) -> io::Result<BenchRun> {
        let running = Arc::new(AtomicBool::new(true));
        let sender_thread = spawn_sender(&self.sender, burst, &running)?;

        let mut bytes = 0usize;
        let mut loop_iterations = 0usize;
        let mut packets = 0usize;
        let start = Instant::now();

        while start.elapsed() < duration {
            let mut handled = 0usize;
            time::timeout(
                recv_timeout(),
                self.receiver
                    .recv_batch(&self.receiver_socket, &self.pool, |packet, _from| {
                        packets += 1;
                        bytes += packet.len();
                        handled += 1;
                        simulate_packet_processing();
                        Ok::<(), io::Error>(())
                    }),
            )
            .await
            .map_err(|_| {
                io::Error::other("batched receiver timed out during concurrent benchmark")
            })?
            .map_err(|err| {
                match err {
                    RecvBatchError::Io(source) => source,
                    RecvBatchError::Handler(source) => source,
                }
            })?;
            if handled == 0 {
                return Err(io::Error::other(
                    "batched benchmark receiver made no progress",
                ));
            }
            loop_iterations += 1;
        }

        finish_sender(&running, sender_thread)?;

        Ok(BenchRun {
            stats: BenchStats {
                packets,
                loop_iterations,
                bytes,
            },
            receive_duration: start.elapsed(),
        })
    }
}

fn bind_receiver_socket(bind_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = StdUdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    SockRef::from(&socket).set_recv_buffer_size(SOCKET_BUFFER_BYTES)?;
    UdpSocket::from_std(socket)
}

fn summarize(runs: &[BenchRun]) -> Summary {
    let mut throughputs = runs
        .iter()
        .map(|run| format_throughput(run.stats.bytes, run.receive_duration))
        .collect::<Vec<_>>();
    throughputs.sort_by(f64::total_cmp);
    Summary {
        run: *runs.last().expect("at least one benchmark run"),
        throughput_mib_s: throughputs[throughputs.len() / 2],
    }
}

fn format_throughput(bytes: usize, duration: Duration) -> f64 {
    bytes as f64 / duration.as_secs_f64() / (1024.0 * 1024.0)
}

fn print_result(label: &str, batch_size: Option<usize>, summary: Summary, gain_pct: Option<f64>) {
    match batch_size {
        Some(batch_size) => {
            println!(
                "{label:>12} batch_size={batch_size:>2} packets={} recv_loops={} bytes={} throughput={:.2} MiB/s gain_vs_single={:+.2}%",
                summary.run.stats.packets,
                summary.run.stats.loop_iterations,
                summary.run.stats.bytes,
                summary.throughput_mib_s,
                gain_pct.unwrap_or(0.0),
            )
        }
        None => {
            println!(
                "{label:>12} packets={} recv_loops={} bytes={} throughput={:.2} MiB/s",
                summary.run.stats.packets,
                summary.run.stats.loop_iterations,
                summary.run.stats.bytes,
                summary.throughput_mib_s,
            )
        }
    }
}

fn relative_gain_pct(baseline: f64, candidate: f64) -> f64 {
    ((candidate / baseline) - 1.0) * 100.0
}

fn simulate_packet_processing() {
    let start = Instant::now();
    while start.elapsed() < work_duration() {
        std::hint::spin_loop();
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn benchmark_duration() -> Duration {
    Duration::from_millis(env_usize("UDP_BATCH_DURATION_MS", DURATION_MS as usize) as u64)
}

fn work_duration() -> Duration {
    Duration::from_micros(env_usize("UDP_BATCH_WORK_US", WORK_US as usize) as u64)
}

fn recv_timeout() -> Duration {
    Duration::from_millis(env_usize("UDP_BATCH_RECV_TIMEOUT_MS", RECV_TIMEOUT_MS as usize) as u64)
}

fn veth_endpoints() -> BenchEndpoints {
    static ENDPOINTS: OnceLock<BenchEndpoints> = OnceLock::new();
    *ENDPOINTS.get_or_init(|| {
        ensure_veth_namespace();
        configure_veth_pair().expect("configure veth pair for benchmark");
        BenchEndpoints {
            sender_bind: format!("{VETH_LEFT_IP}:0")
                .parse()
                .expect("parse veth sender bind address"),
            receiver_bind: format!("{VETH_RIGHT_IP}:0")
                .parse()
                .expect("parse veth receiver bind address"),
        }
    })
}

fn ensure_veth_namespace() {
    if !cfg!(target_os = "linux") {
        panic!("UDP batch veth benchmark is only supported on Linux");
    }
    if env::var_os(UDP_BATCH_VETH_NAMESPACE_ENV).is_some() {
        return;
    }

    let current_exe = env::current_exe().expect("resolve benchmark executable path");
    let status = Command::new("unshare")
        .args(["-Urn", "--"])
        .arg(&current_exe)
        .args(env::args_os().skip(1))
        .env(UDP_BATCH_VETH_NAMESPACE_ENV, "1")
        .status()
        .unwrap_or_else(|error| panic!("launch benchmark in private namespace: {error}"));
    exit_with_status(status);
}

fn exit_with_status(status: ExitStatus) -> ! {
    std::process::exit(status.code().unwrap_or(1));
}

fn configure_veth_pair() -> io::Result<()> {
    static CONFIGURED: OnceLock<()> = OnceLock::new();
    if CONFIGURED.get().is_some() {
        return Ok(());
    }

    let left_cidr = format!("{VETH_LEFT_IP}/30");
    let right_cidr = format!("{VETH_RIGHT_IP}/30");
    run_ip([
        "link",
        "add",
        VETH_LEFT_NAME,
        "type",
        "veth",
        "peer",
        "name",
        VETH_RIGHT_NAME,
    ])?;
    run_ip(["addr", "add", left_cidr.as_str(), "dev", VETH_LEFT_NAME])?;
    run_ip(["addr", "add", right_cidr.as_str(), "dev", VETH_RIGHT_NAME])?;
    run_ip(["link", "set", "lo", "up"])?;
    run_ip(["link", "set", VETH_LEFT_NAME, "up"])?;
    run_ip(["link", "set", VETH_RIGHT_NAME, "up"])?;
    let _ = CONFIGURED.set(());
    Ok(())
}

fn run_ip<const N: usize>(args: [&str; N]) -> io::Result<()> {
    let output = Command::new("ip").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "ip {} failed: {}",
        args.join(" "),
        stderr.trim()
    )))
}

fn run_single_case(burst: &[Vec<u8>], duration: Duration) -> BenchRun {
    runtime()
        .block_on(async {
            let mut scenario = NonBatchedScenario::new().await?;
            scenario.run(burst, duration).await
        })
        .expect("run single benchmark")
}

fn run_batched_case<const BATCH_SIZE: usize>(burst: &[Vec<u8>], duration: Duration) -> BenchRun {
    runtime()
        .block_on(async {
            let mut scenario = BatchedScenario::<BATCH_SIZE>::new().await?;
            scenario.run(burst, duration).await
        })
        .expect("run batched benchmark")
}

fn measure_case<F>(warmup_samples: usize, measure_samples: usize, mut run_case: F) -> Summary
where
    F: FnMut() -> BenchRun,
{
    for _ in 0..warmup_samples {
        let warmup = run_case();
        std::hint::black_box((
            warmup.stats.packets,
            warmup.stats.bytes,
            warmup.stats.loop_iterations,
            warmup.receive_duration,
        ));
    }

    let mut runs = Vec::with_capacity(measure_samples);
    for _ in 0..measure_samples {
        runs.push(run_case());
    }
    summarize(&runs)
}

fn main() {
    let _endpoints = veth_endpoints();
    let _args: Vec<String> = env::args().collect();
    let warmup_samples = env_usize("UDP_BATCH_WARMUP", WARMUP_SAMPLES);
    let measure_samples = env_usize("UDP_BATCH_SAMPLES", MEASURE_SAMPLES).max(1);
    let duration = benchmark_duration();
    println!(
        "udp_batch benchmark: duration_ms={} work_us={} packet_size={} sender_burst={} warmup_samples={} measure_samples={} socket_buffer_bytes={}",
        duration.as_millis(),
        work_duration().as_micros(),
        BENCH_PACKET_SIZE,
        SENDER_BURST_SIZE,
        warmup_samples,
        measure_samples,
        SOCKET_BUFFER_BYTES,
    );

    let burst = burst_payloads(SENDER_BURST_SIZE);
    let single_summary = measure_case(warmup_samples, measure_samples, || {
        run_single_case(&burst, duration)
    });
    print_result(
        BenchmarkVariant::Single.to_string().as_str(),
        None,
        single_summary,
        None,
    );

    for batch_size in BATCH_SIZES {
        let batched_summary = measure_case(warmup_samples, measure_samples, || {
            match batch_size {
                16 => run_batched_case::<16>(&burst, duration),
                32 => run_batched_case::<32>(&burst, duration),
                64 => run_batched_case::<64>(&burst, duration),
                _ => panic!("unsupported benchmark batch size: {batch_size}"),
            }
        });
        let gain_pct = relative_gain_pct(
            single_summary.throughput_mib_s,
            batched_summary.throughput_mib_s,
        );
        print_result(
            BenchmarkVariant::Batched.to_string().as_str(),
            Some(batch_size),
            batched_summary,
            Some(gain_pct),
        );
    }
}
