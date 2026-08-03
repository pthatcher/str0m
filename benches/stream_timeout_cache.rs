//! Benchmark for [`RtcConfig::enable_stream_timeout_cache`].
//!
//! Exists so a reviewer can decide for themselves whether the cache earns its
//! complexity. It runs the same workload twice, once with the cache off and once with
//! it on, and reports the difference next to the cost of the SRTP crypto for the same
//! packets - the yardstick being that if the saving is small compared to work that can
//! never be removed, the cache is not worth much.
//!
//! ```text
//! cargo bench --bench stream_timeout_cache
//! ```
//!
//! Results move around a lot on a busy machine. For something you can trust, pin it:
//!
//! ```text
//! taskset -c 3 cargo bench --bench stream_timeout_cache
//! ```
//!
//! `SECONDS` sets the simulated seconds per run and `ROUNDS` the number of repetitions.
//! The benchmark prints the spread across rounds and warns when it is wide.
//!
//! For the other half of the question - whether the cache changes behaviour - the test
//! suite runs either way:
//!
//! ```text
//! cargo test                            # cache off, the default
//! STREAM_TIMEOUT_CACHE=1 cargo test     # cache on
//! ```
//!
//! # The scenario
//!
//! One SFU connection. The peer under test (`l`) carries:
//!
//! * ingress: 1 audio stream and 3 simulcast video layers (512kbit, 1Mbit, 2Mbit)
//! * egress: 3 audio streams of which only the active speaker sends, and 9 video
//!   streams at 1Mbit each
//!
//! The other peer (`r`) is the mirror of that, so it stands in for the client. Packet
//! rates and payload sizes are derived from the bitrates, and video is sent in per-frame
//! bursts rather than evenly spaced. Edit [`egress_specs`] and [`ingress_specs`] to
//! measure a different shape.

use std::time::{Duration, Instant};

use str0m::Rtc;
use str0m::crypto::AeadAes256Gcm;
use str0m::media::{MediaKind, Mid, Pt};
use str0m::rtp::{RtpWrite, Ssrc};

#[path = "../tests/common.rs"]
mod common;
use common::{TestRtc, connect_l_r_with_rtc, init_crypto_default, progress};

/// Opus bitrate, used to size audio packets.
const AUDIO_BITRATE: u32 = 40_000;

/// One opus frame per 20ms.
const AUDIO_PTIME: Duration = Duration::from_millis(20);

/// Opus runs on a 48kHz clock.
const AUDIO_CLOCK_RATE: u32 = 48_000;

/// Video frame rate. Determines how often a burst of packets is sent.
const VIDEO_FPS: u32 = 30;

/// Video runs on a 90kHz clock.
const VIDEO_CLOCK_RATE: u32 = 90_000;

/// Largest RTP payload we put on the wire, leaving room for headers and the SRTP tag.
const MAX_PAYLOAD: usize = 1100;

/// A stream in the connection, described the way an SFU operator would.
#[derive(Debug, Clone, Copy)]
struct MediaSpec {
    kind: MediaKind,
    /// Target bitrate in bits per second.
    bitrate: u32,
    /// Whether this stream actually sends. Inactive streams are declared and swept like
    /// any other, but never carry packets - like the audio of everyone who isn't
    /// currently the active speaker.
    active: bool,
}

impl MediaSpec {
    const fn audio(active: bool) -> Self {
        MediaSpec {
            kind: MediaKind::Audio,
            bitrate: AUDIO_BITRATE,
            active,
        }
    }

    const fn video(bitrate: u32) -> Self {
        MediaSpec {
            kind: MediaKind::Video,
            bitrate,
            active: true,
        }
    }
}

/// What the SFU sends to the client.
///
/// Three audio streams, of which only the active speaker is sending, and nine video
/// streams forwarded from other participants.
fn egress_specs() -> Vec<MediaSpec> {
    let mut specs = vec![
        MediaSpec::audio(true),
        MediaSpec::audio(false),
        MediaSpec::audio(false),
    ];

    specs.extend((0..9).map(|_| MediaSpec::video(1_000_000)));

    specs
}

/// What the client sends to the SFU: one audio stream and three simulcast layers.
fn ingress_specs() -> Vec<MediaSpec> {
    vec![
        MediaSpec::audio(true),
        MediaSpec::video(512_000),
        MediaSpec::video(1_000_000),
        MediaSpec::video(2_000_000),
    ]
}

/// How a spec turns into packets on the wire.
#[derive(Debug, Clone, Copy)]
struct Cadence {
    /// Time between bursts: one audio packet, or one video frame.
    interval: Duration,
    /// Packets per burst.
    packets_per_burst: usize,
    /// Payload size of each packet in a burst.
    payload_len: usize,
    /// RTP clock ticks between bursts.
    ticks_per_burst: u32,
}

impl Cadence {
    fn new(spec: MediaSpec) -> Self {
        let (interval, bursts_per_second, clock_rate) = match spec.kind {
            MediaKind::Audio => {
                let per_second = 1_000 / AUDIO_PTIME.as_millis() as u32;
                (AUDIO_PTIME, per_second, AUDIO_CLOCK_RATE)
            }
            MediaKind::Video => (
                Duration::from_nanos(1_000_000_000 / VIDEO_FPS as u64),
                VIDEO_FPS,
                VIDEO_CLOCK_RATE,
            ),
        };

        // Bytes this stream puts on the wire per burst, split over MTU sized packets.
        let bytes_per_burst = (spec.bitrate / 8 / bursts_per_second) as usize;
        let packets_per_burst = bytes_per_burst.div_ceil(MAX_PAYLOAD).max(1);

        Cadence {
            interval,
            packets_per_burst,
            payload_len: bytes_per_burst / packets_per_burst,
            ticks_per_burst: clock_rate / bursts_per_second,
        }
    }

    fn packets_per_second(&self) -> f64 {
        self.packets_per_burst as f64 / self.interval.as_secs_f64()
    }
}

/// A declared stream plus the state needed to keep it sending at its bitrate.
struct Sender {
    ssrc: Ssrc,
    pt: Pt,
    kind: MediaKind,
    active: bool,
    cadence: Cadence,

    next_at: Instant,
    seq_no: u64,
    time: u32,
}

impl Sender {
    fn new(spec: MediaSpec, ssrc: Ssrc, pt: Pt, start: Instant) -> Self {
        Sender {
            ssrc,
            pt,
            kind: spec.kind,
            active: spec.active,
            cadence: Cadence::new(spec),
            next_at: start,
            seq_no: 1000,
            time: 100_000,
        }
    }
}

/// What a run did, used to sanity check that both configurations carried the same media.
#[derive(Debug, Default, Clone, Copy)]
struct Work {
    /// RTP packets written across both peers.
    packets: u64,
    /// Payload bytes written across both peers.
    payload_bytes: u64,
}

impl Work {
    fn mean_payload(&self) -> usize {
        (self.payload_bytes / self.packets.max(1)) as usize
    }
}

struct Scenario {
    l: TestRtc,
    r: TestRtc,
    /// Streams `l` sends, i.e. the SFU's egress.
    l_senders: Vec<Sender>,
    /// Streams `r` sends, i.e. the SFU's ingress.
    r_senders: Vec<Sender>,
}

/// Builds a connected pair shaped like an SFU connection.
///
/// The DTLS handshake and stream setup happen here so they stay out of the measurement.
fn setup(cache: bool) -> Scenario {
    let now = Instant::now();

    let build = || {
        Rtc::builder()
            .set_rtp_mode(true)
            .enable_stream_timeout_cache(cache)
            .build(now)
    };

    let (mut l, mut r) = connect_l_r_with_rtc(build(), build());

    let audio_pt = l.params_opus().pt();
    let video_pt = l.params_vp8().pt();

    // Whatever one peer declares as a send stream, the other expects as a receive stream.
    let declare = |sender: &mut TestRtc,
                   receiver: &mut TestRtc,
                   specs: Vec<MediaSpec>,
                   prefix: &str,
                   ssrc_base: u32| {
        let mut senders = Vec::with_capacity(specs.len());

        for (i, spec) in specs.into_iter().enumerate() {
            let mid: Mid = format!("{prefix}{i}").as_str().into();
            let ssrc: Ssrc = (ssrc_base + i as u32).into();

            // Video gets an RTX stream, so the RTX cache is exercised on every packet
            // like it would be in a real deployment.
            let (pt, rtx) = match spec.kind {
                MediaKind::Audio => (audio_pt, None),
                MediaKind::Video => (video_pt, Some((ssrc_base + 500 + i as u32).into())),
            };

            sender.direct_api().declare_media(mid, spec.kind);
            sender.direct_api().declare_stream_tx(ssrc, rtx, mid, None);

            receiver.direct_api().declare_media(mid, spec.kind);
            receiver.direct_api().expect_stream_rx(ssrc, rtx, mid, None);

            senders.push(Sender::new(spec, ssrc, pt, sender.last));
        }

        senders
    };

    let l_senders = declare(&mut l, &mut r, egress_specs(), "e", 1000);
    let r_senders = declare(&mut r, &mut l, ingress_specs(), "i", 5000);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    Scenario {
        l,
        r,
        l_senders,
        r_senders,
    }
}

/// Writes whatever is due on each stream of one peer.
fn pump(rtc: &mut TestRtc, senders: &mut [Sender], payload: &[u8], work: &mut Work) {
    let now = rtc.last;

    for sender in senders.iter_mut() {
        if !sender.active {
            continue;
        }

        while sender.next_at <= now {
            let wallclock = sender.next_at;
            let burst = sender.cadence.packets_per_burst;

            for i in 0..burst {
                // The marker bit ends a video frame.
                let marker = i == burst - 1;

                let mut direct = rtc.direct_api();
                let stream = direct.stream_tx(&sender.ssrc).expect("declared stream");

                stream.write_rtp(
                    RtpWrite::new(
                        sender.pt,
                        sender.seq_no.into(),
                        sender.time,
                        wallclock,
                        &payload[..sender.cadence.payload_len],
                    )
                    .marker(marker)
                    .nackable(sender.kind == MediaKind::Video),
                );

                sender.seq_no += 1;
                work.packets += 1;
                work.payload_bytes += sender.cadence.payload_len as u64;
            }

            sender.time = sender.time.wrapping_add(sender.cadence.ticks_per_burst);
            sender.next_at += sender.cadence.interval;
        }
    }
}

/// Pumps the scenario until `duration` of simulated time has passed.
fn run(scenario: &mut Scenario, duration: Duration, payload: &[u8]) -> Work {
    let Scenario {
        l,
        r,
        l_senders,
        r_senders,
    } = scenario;

    let mut work = Work::default();

    while l.duration() < duration {
        pump(l, l_senders, payload, &mut work);
        pump(r, r_senders, payload, &mut work);

        progress(l, r).expect("clean progress");

        // Otherwise the event log grows for the entire run and skews the measurement.
        l.events.clear();
        r.events.clear();
    }

    work
}

/// One round of the comparison.
///
/// The cache-off run, the cache-on run and the SRTP yardstick are all measured back to
/// back, so a shift in machine speed part way through the benchmark moves all three
/// together and the ratios below stay meaningful.
///
/// Timings are normalised per packet. The scenario is not bit-deterministic - the order
/// str0m walks its stream maps varies between `Rtc` instances, which shifts packet
/// interleaving slightly - so two runs of the *same* configuration differ by a fraction
/// of a percent in packet count. Dividing by packets removes that.
#[derive(Debug, Clone, Copy)]
struct Round {
    /// Nanoseconds per packet with the cache off.
    off: f64,
    /// Nanoseconds per packet with the cache on.
    on: f64,
    /// Nanoseconds per packet for SRTP encrypt plus decrypt.
    srtp: f64,
    packets: u64,
}

impl Round {
    fn speedup(&self) -> f64 {
        self.off / self.on
    }

    /// Share of the uncached per-packet cost that the cache removes.
    fn removed(&self) -> f64 {
        1.0 - self.on / self.off
    }

    /// Share of the uncached per-packet cost that is SRTP.
    fn srtp_share(&self) -> f64 {
        self.srtp / self.off
    }

    /// The saving expressed in units of "one SRTP encrypt plus decrypt".
    fn vs_srtp(&self) -> f64 {
        (self.off - self.on) / self.srtp
    }
}

fn measure_round(duration: Duration, payload: &[u8]) -> Round {
    let (off_elapsed, off_work) = time_one(false, duration, payload);
    let (on_elapsed, on_work) = time_one(true, duration, payload);

    // Both runs should be carrying essentially the same media. A real divergence would
    // mean we are timing different workloads and the comparison is meaningless.
    let ratio = off_work.packets as f64 / on_work.packets as f64;
    assert!(
        (0.95..=1.05).contains(&ratio),
        "packet counts diverged: {} vs {}",
        off_work.packets,
        on_work.packets
    );

    let per_packet =
        |elapsed: Duration, work: Work| elapsed.as_secs_f64() * 1e9 / work.packets as f64;

    Round {
        off: per_packet(off_elapsed, off_work),
        on: per_packet(on_elapsed, on_work),
        srtp: srtp_cost_per_packet(off_work.mean_payload()).as_secs_f64() * 1e9,
        packets: off_work.packets,
    }
}

fn time_one(cache: bool, duration: Duration, payload: &[u8]) -> (Duration, Work) {
    let mut scenario = setup(cache);

    let start = Instant::now();
    let work = run(&mut scenario, duration, payload);

    (start.elapsed(), work)
}

/// Times one SRTP encrypt plus one decrypt of a packet-sized buffer.
///
/// This is the yardstick the numbers should be read against: it is the unavoidable
/// per-packet cost of SRTP, so it says whether the bookkeeping the cache removes was
/// worth anything next to the work that cannot be removed.
///
/// Uses AEAD-AES-256-GCM, which is the profile str0m prefers.
fn srtp_cost_per_packet(payload_len: usize) -> Duration {
    const BATCHES: usize = 3;
    const ROUNDS: usize = 2_000;

    let provider = str0m::crypto::from_feature_flags();
    let aead = provider.srtp_provider.aead_aes_256_gcm();

    let mut enc = aead.create_cipher([7; 32], true);
    let mut dec = aead.create_cipher([7; 32], false);

    let plain = vec![0_u8; payload_len];
    let aad = [0_u8; 12];
    let iv = [0_u8; 12];

    let mut encrypted = vec![0_u8; payload_len + AeadAes256Gcm::TAG_LEN];
    let mut decrypted = vec![0_u8; payload_len];

    let mut best = Duration::MAX;

    // A batch is only a few milliseconds, short enough that one scheduling hiccup would
    // dominate it. Best of a handful, still all within this round.
    for _ in 0..BATCHES {
        let start = Instant::now();

        for _ in 0..ROUNDS {
            enc.encrypt(&iv, &aad, &plain, &mut encrypted)
                .expect("encrypt");
            dec.decrypt(&iv, &[&aad], &encrypted, &mut decrypted)
                .expect("decrypt");
        }

        best = best.min(start.elapsed() / ROUNDS as u32);
    }

    best
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .map(|v| v.trim().parse().expect("a number"))
        .unwrap_or(default)
}

fn env_duration() -> Duration {
    let Ok(v) = std::env::var("SECONDS") else {
        return Duration::from_secs(30);
    };

    Duration::from_secs_f64(v.trim().parse().expect("SECONDS to be a number"))
}

/// Prints one side of the connection, so a run is self documenting.
fn describe(name: &str, specs: &[MediaSpec]) {
    let active = specs.iter().filter(|s| s.active);

    let packet_rate: f64 = active
        .clone()
        .map(|s| Cadence::new(*s).packets_per_second())
        .sum();
    let bitrate: u32 = active.map(|s| s.bitrate).sum();
    let idle = specs.iter().filter(|s| !s.active).count();

    println!(
        "  {name:8} {:2} streams ({idle} idle), {packet_rate:4.0} pkt/s, {:.2} Mbit/s",
        specs.len(),
        bitrate as f64 / 1e6,
    );
}

fn main() {
    init_crypto_default();

    let duration = env_duration();
    let rounds = env_usize("ROUNDS", 5);
    let payload = vec![0_u8; MAX_PAYLOAD];

    println!("str0m stream timeout cache");
    println!("==========================");
    println!();
    println!("Compares RtcConfig::enable_stream_timeout_cache(false) against (true) on");
    println!("one simulated SFU connection:");
    println!();
    describe("egress", &egress_specs());
    describe("ingress", &ingress_specs());
    println!();
    println!(
        "{rounds} rounds of {:.0}s simulated traffic. Within a round the two runs and the",
        duration.as_secs_f64()
    );
    println!("SRTP yardstick are measured back to back, so they share machine conditions.");
    println!();
    println!("For a stable result, run on an idle machine pinned to one core:");
    println!("    taskset -c 3 cargo bench --bench stream_timeout_cache");
    println!("Knobs: SECONDS (simulated seconds per run), ROUNDS (repetitions).");
    println!();

    println!(
        "{:>6}  {:>12}  {:>12}  {:>12}  {:>9}",
        "round", "off ns/pkt", "on ns/pkt", "SRTP ns/pkt", "speedup"
    );

    let mut results = Vec::with_capacity(rounds);

    for i in 0..rounds {
        let round = measure_round(duration, &payload);

        println!(
            "{:>6}  {:>12.0}  {:>12.0}  {:>12.0}  {:>8.2}x",
            i + 1,
            round.off,
            round.on,
            round.srtp,
            round.speedup()
        );

        results.push(round);
    }

    // Report one representative round rather than a per-column median, so every number
    // below comes from the same measurement and they cannot contradict each other.
    results.sort_by(|a, b| a.speedup().total_cmp(&b.speedup()));

    let lo = results[0].speedup();
    let hi = results[results.len() - 1].speedup();
    let mid = results[results.len() / 2];

    println!();
    println!(
        "Middle round of {rounds} ({} packets per run):",
        mid.packets
    );
    println!(
        "  per-packet cost    {:.0} ns  ->  {:.0} ns",
        mid.off, mid.on
    );
    println!(
        "  speedup            {:.2}x   (range {lo:.2}x - {hi:.2}x)",
        mid.speedup()
    );
    println!(
        "  cost removed       {:.0}% of the uncached per-packet cost",
        mid.removed() * 100.0
    );
    println!(
        "  SRTP costs         {:.0}% of the uncached per-packet cost",
        mid.srtp_share() * 100.0
    );
    println!(
        "  so the cache saves {:.1}x what SRTP encrypt+decrypt costs per packet",
        mid.vs_srtp()
    );

    if hi - lo > 0.25 {
        println!();
        println!(
            "NOTE: the speedup varied by {:.2}x across rounds, which is wide enough that",
            hi - lo
        );
        println!("the middle round may not mean much. Pin to a core, close other work,");
        println!("or raise ROUNDS.");
    }
}
