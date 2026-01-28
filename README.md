# AirPlay 2 Sender

An open-source Rust implementation of an AirPlay 2 audio transmitter (sender).

## Project Status

**Pre-alpha** (as of January 2026).

- Discovery, pairing, RTSP session setup, and audio streaming are functional.
- Many modules still contain `todo!()` stubs.
- The public API is **unstable**.

## Prerequisites

### macOS

- Xcode Command Line Tools: `xcode-select --install`
- Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

No Homebrew packages are required. All native dependencies (FDK-AAC, ALAC, crypto) are either pure Rust or compile from vendored C source automatically.

### Linux (Debian/Ubuntu/Raspberry Pi OS)

```bash
sudo apt-get install build-essential pkg-config git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Or run the setup script to install everything:

```bash
./setup-deps.sh
```

## Building

```bash
# Build all crates
cargo build --workspace

# Build in release mode
cargo build --workspace --release

# Run tests
cargo test --workspace
```

### Cross-compilation (for Raspberry Pi)

```bash
# Build for Pi 3/4/5/Zero 2 W (64-bit)
./utils/cross-compile.sh aarch64-unknown-linux-gnu

# Build for Pi 2/3/4/Zero 2 (32-bit)
./utils/cross-compile.sh armv7-unknown-linux-gnueabihf

# Build for Pi Zero/1 (ARMv6)
./utils/cross-compile.sh arm-unknown-linux-gnueabihf
```

## Quick Start

### 1. Discover devices on your network

```bash
cargo run -p airplay-discovery --example debug_devices
```

Shows all AirPlay devices with their IP addresses, model, features, AirPlay 2 / PTP support, and pairing requirements.

Options:
- `--raw-only` - Show only raw mDNS TXT records
- `--info` - Query each device's `/info` HTTP endpoint

### 2. Pair with a device

```bash
# Interactive - choose device and pairing method from a menu
cargo run -p airplay-pairing --example pair_with_device

# Auto-select by name, model, device ID, or IP
cargo run -p airplay-pairing --example pair_with_device -- --match "HomePod"

# Non-interactive transient pairing + encrypted RTSP session
cargo run -p airplay-pairing --example pair_with_device -- --match "HomePod" --mode transient-rtsp --pin 3939

# Auto-select via environment variable
AIRPLAY_DEVICE_MATCH="AudioAccessory5,1" cargo run -p airplay-pairing --example pair_with_device
```

Pairing methods available:
- **True Transient (Ed25519)** - No PIN, for devices with `pw=false`
- **SRP Transient (M1-M4)** - PIN required, no persistent registration
- **Full SRP (M1-M6)** - PIN required, registers your key with the device
- **Pair-Verify (TLV8)** - Uses a previously registered Ed25519 key
- **Pair-Verify (Raw 68-byte)** - For transient pairing sessions

Identity is persisted per-device at `.airplay_sender_identity_<device_id>.json`.

### 3. Play audio to a device

```bash
# AirPlay 1 / RAOP (no pairing required)
cargo run -p airplay-client --example play_audio -- <ip> <port> <audio-file> --airplay1

# AirPlay 2 (HomeKit pairing, NTP timing)
cargo run -p airplay-client --example play_audio -- <ip> <port> <audio-file> --airplay2

# AirPlay 2 with PTP timing (NOT WORKING YET)
cargo run -p airplay-client --example play_audio -- <ip> <port> <audio-file> --airplay2 --ptp
```

Supported audio formats: MP3, FLAC, WAV, AAC, ALAC, Ogg Vorbis, and more (via symphonia).

### 4. Debug RTSP SETUP

```bash
cargo run -p airplay-client --example debug_setup -- <ip> <port>
```

Connects, pairs, and runs the two-phase RTSP SETUP handshake with verbose logging.

### 5. Terminal UI

```bash
cargo run -p airplay-tui

# With debug logging to file
cargo run -p airplay-tui -- --debug
cargo run -p airplay-tui -- --debug --log-file /tmp/airplay.log
```

Full terminal interface with device browser, file picker, playback controls, and multi-room group management.

## Timing Synchronization: PTP vs NTP

This implementation supports two timing protocols for clock synchronization between sender and receiver.

### NTP-style Timing ✓ Working

**When to use**: AirPlay 1 devices and AirPlay 2 playback (including HomePod).

NTP timing uses a simple request-response protocol on an ephemeral UDP port negotiated during SETUP:
- Receiver sends timing requests (RTP PT=82) to the sender
- Sender responds with timestamps (RTP PT=83)
- Four-timestamp exchange calculates clock offset and round-trip delay
- Millisecond-level accuracy, sufficient for single-device playback

**Usage**:
```bash
cargo run -p airplay-client --example play_audio -- <ip> <port> <file> --airplay2
```

### PTP Timing (Multi-room) ⚠️ Experimental

**When to use**: AirPlay 2 multi-room synchronization and HomePod.

**Status**: PTP implementation is in progress but not yet confirmed working with real devices.

PTP (IEEE 1588) is intended to provide sub-millisecond synchronization required for multi-room audio:
- Uses UDP ports **319** (event) and **320** (general) - these are privileged ports
- Implements IEEE 1588 protocol with Sync, Follow_Up, Delay_Req, Delay_Resp, and Announce messages
- The sender acts as PTP master (sending Sync messages) or slave (syncing to receiver's clock)
- Required by HomePod and devices advertising `SupportsPTP` (feature bit 41)

**Usage**:
```bash
# Requires root/sudo for privileged ports 319/320
sudo cargo run -p airplay-client --example play_audio -- <ip> <port> <file> --airplay2 --ptp
```

**Port fallback**: If ports 319/320 are unavailable, the code automatically falls back to ephemeral ports. However, some receivers (especially HomePod) may reject non-standard PTP ports.

### Implementation Notes

- **NTP** is implemented in `crates/airplay-timing/src/ntp.rs` (working)
- **PTP** is implemented in `crates/airplay-timing/src/ptp.rs` (experimental)
- Both protocols implement the `TimingProtocol` trait for clock offset calculation
- The timing protocol is negotiated during RTSP SETUP Phase 1 (`timingProtocol: "NTP"` or `timingProtocol: "PTP"`)

## Real-time Audio on Raspberry Pi

The audio streamer is optimized for low-jitter playback on resource-constrained devices like the Raspberry Pi Zero 2 W:

- **Dedicated sender thread** with `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME)` and `SCHED_FIFO` real-time priority achieves ~5 microsecond average jitter (vs ~1.5ms with async sleep)
- **Retransmit handling** for UDP packet loss — parses Apple's 8-byte compact retransmit request format and responds within 5ms
- **DSCP EF marking** on audio sockets for WiFi WMM Voice priority

### Recommended Pi setup for best audio quality

```bash
# Disable WiFi power management (prevents radio sleep between packets)
sudo iwconfig wlan0 power off

# Run with root for SCHED_FIFO real-time priority
sudo ./play_audio <ip> <port> <file> --airplay2
```

## Notes

- **HomePod**: Works with AirPlay 2 and NTP timing (`--airplay2`). PTP timing is experimental.
- **Transient pairing**: HomePod and HomeKit devices accept SRP transient pairing (M1-M4) with PIN `3939`. No pair-verify step is needed afterward.

## Architecture

```
airplay2-sender/
├── crates/
│   ├── airplay-core/        # Core types, traits, errors
│   ├── airplay-discovery/   # mDNS/Bonjour device discovery
│   ├── airplay-crypto/      # Cryptographic operations (SRP, ECDH, ChaCha20)
│   ├── airplay-pairing/     # HomeKit + FairPlay authentication
│   ├── airplay-rtsp/        # RTSP protocol + session management
│   ├── airplay-audio/       # Audio decoding, ALAC/AAC encoding, RTP
│   ├── airplay-timing/      # PTP (IEEE 1588) and NTP synchronization
│   ├── airplay-client/      # High-level client API
│   └── airplay-tui/         # Terminal user interface
```

## Library Usage

The high-level client API (planned, not yet stable):

```rust
use airplay_client::{AirPlayClient, ClientBuilder};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ClientBuilder::new()
        .airplay2()
        .buffer_duration_ms(2000)
        .build()?;

    let devices = client.discover(Duration::from_secs(5)).await?;

    if let Some(device) = devices.iter().find(|d| d.supports_airplay2()) {
        client.connect(device).await?;
        client.play_file("song.mp3").await?;
        client.wait_for_completion().await?;
    }

    Ok(())
}
```

For lower-level pairing control, use `airplay-pairing` directly:

```rust
use airplay_pairing::{PairingSession, PairingStep};

let mut session = PairingSession::new_transient();
let mut step = session.transient_pairing_start("3939")?;

loop {
    step = match step {
        PairingStep::Send(request) => {
            let response = send_pair_setup(request)?;
            session.transient_pairing_continue(response)?
        }
        PairingStep::Complete(keys) => {
            use_keys(keys);
            break;
        }
    };
}
```

## Dependencies

Key dependencies (all pure Rust except FDK-AAC which compiles from vendored C source):

- `tokio` - Async runtime
- `mdns-sd` - mDNS service discovery (pure Rust, no Avahi/Bonjour dependency)
- `symphonia` - Audio decoding (MP3, FLAC, WAV, AAC, ALAC, Ogg, etc.)
- `alac-encoder` - ALAC encoding (pure Rust)
- `fdk-aac` - AAC encoding (vendored C source, compiled via `cc`)
- `x25519-dalek`, `ed25519-dalek` - Elliptic curve crypto
- `chacha20poly1305` - AEAD encryption
- `num-bigint` - SRP big integer math
- `plist` - Binary plist encoding
- `ratatui` - Terminal UI framework

## Protocol References

- shairport-sync (C) - Production AirPlay 2 receiver
- openairplay documentation

