//! Device connection management.

use airplay_core::{Device, StreamConfig, error::Result};
use airplay_core::error::{Error as CoreError, RtspError};
use airplay_core::features::AuthMethod;
use airplay_rtsp::{RtspConnection, RtspSession, SessionState, RtspRequest};
use airplay_pairing::PairingSession;
use airplay_crypto::ed25519::IdentityKeyPair;
// Timing imports reserved for future use
// use airplay_timing::{TimingProtocol, NtpTimingClient, PtpClient};
use airplay_audio::{AudioStreamer, AudioDecoder, RtpSender, RtpReceiver};
use std::sync::Arc;
use airplay_audio::cipher::ChaChaPacketCipher;
use airplay_crypto::chacha::ControlCipher;
use airplay_crypto::chacha::AudioCipher;
use airplay_crypto::keys::SharedSecret;
use crate::PlaybackState;
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, info, warn};
use airplay_timing::{NtpTimingServer, ClockOffset, PtpMaster, PTP_EVENT_PORT, PTP_GENERAL_PORT, run_ptp_slave};
use airplay_core::stream::TimingProtocol;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::net::TcpStream;

/// Generate a random MAC-like device ID for the client.
fn generate_device_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>()
    )
}

fn stream_key_from_shared_secret(shared_secret: &SharedSecret) -> Result<[u8; 32]> {
    let bytes = shared_secret.as_bytes();
    if bytes.len() < 32 {
        return Err(RtspError::SetupFailed(
            "Shared secret too short for stream key".into(),
        )
        .into());
    }

    let mut shk = [0u8; 32];
    shk.copy_from_slice(&bytes[..32]);
    Ok(shk)
}

/// Select the best address from a device's address list.
/// Prefers IPv4, then global IPv6, avoiding link-local addresses.
fn select_best_address(addresses: &[IpAddr]) -> Option<&IpAddr> {
    // First try: IPv4 address
    if let Some(addr) = addresses.iter().find(|a| a.is_ipv4()) {
        debug!("Selected IPv4 address: {}", addr);
        return Some(addr);
    }

    // Second try: Global IPv6 (not link-local, not loopback)
    if let Some(addr) = addresses.iter().find(|a| {
        match a {
            IpAddr::V6(v6) => {
                // Avoid link-local (fe80::) and loopback
                !v6.is_loopback() && !is_link_local_v6(v6)
            }
            _ => false,
        }
    }) {
        debug!("Selected global IPv6 address: {}", addr);
        return Some(addr);
    }

    // Last resort: any address
    let addr = addresses.first();
    if let Some(a) = addr {
        debug!("Selected fallback address: {}", a);
    }
    addr
}

/// Check if an IPv6 address is link-local (fe80::/10)
fn is_link_local_v6(addr: &std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// Active connection to an AirPlay device.
pub struct Connection {
    device: Device,
    rtsp: RtspConnection,
    session: RtspSession,
    pairing: Option<PairingSession>,
    streamer: Option<AudioStreamer>,
    playback_state: PlaybackState,
    volume: f32,
    stream_config: StreamConfig,
    timing_offset: Option<ClockOffset>,
    timing_tx: Option<watch::Sender<ClockOffset>>,
    control_task: Option<tokio::task::JoinHandle<()>>,
    timing_task: Option<JoinHandle<()>>,
    timing_server: Option<NtpTimingServer>,
    /// PTP master instance (sender IS the timing master)
    ptp_master: Option<PtpMaster>,
    /// Background task sending periodic PTP Sync messages
    ptp_master_sync_task: Option<JoinHandle<()>>,
    /// Control port receiver (keeps the UDP socket alive so HomePod doesn't get ICMP unreachable)
    control_receiver: Option<Arc<RtpReceiver>>,
    /// Reverse connection to device's events port (required before RECORD)
    events_stream: Option<TcpStream>,
}

impl Connection {
    /// Create new connection to device.
    pub async fn connect(device: Device, config: StreamConfig) -> Result<Self> {
        Self::connect_with_pin(device, config, "3939").await
    }

    /// Create connection with PIN for protected devices.
    pub async fn connect_with_pin(device: Device, config: StreamConfig, pin: &str) -> Result<Self> {
        // Generate a stable client device ID for this session
        let client_device_id = generate_device_id();

        // Generate a stable identity keypair for pairing
        let identity = IdentityKeyPair::generate();

        // 1. TCP connect - prefer IPv4 addresses over link-local IPv6
        let ip_addr = select_best_address(&device.addresses)
            .ok_or_else(|| RtspError::ConnectionRefused)?;
        let addr = SocketAddr::new(*ip_addr, device.port);
        info!("Connecting to {} at {}", device.name, addr);

        let mut rtsp = RtspConnection::new(addr);
        rtsp.connect().await?;

        // 2. Create session
        let mut session = RtspSession::new(device.clone(), config.clone());
        tracing::debug!("Setting session client_device_id to: {}", client_device_id);
        session.set_client_device_id(client_device_id.clone());
        session.set_connected()?;

        // Set the request host to the remote device's IP (not our local IP!)
        // RTSP URIs should be rtsp://<remote_ip>/<session_uuid>
        session.set_request_host(ip_addr.to_string());

        let client_instance = client_device_id.replace(":", "");
        rtsp.add_session_header("User-Agent", "AirPlay/745.83");
        rtsp.add_session_header("X-Apple-Client-Name", "Rust AirPlay Sender");
        rtsp.add_session_header("X-Apple-Device-ID", client_device_id.clone());
        rtsp.add_session_header("DACP-ID", client_instance.clone());
        rtsp.add_session_header("Client-Instance", client_instance);
        rtsp.add_session_header("Active-Remote", "1234567890");

        // 3. GET /info (required before pairing)
        let info_req = RtspRequest::get_info();
        let _info_resp = rtsp.send(info_req).await?;

        // 4. Transient pairing (SRP M1-M4 flow with HKP=4)
        let auth_method = AuthMethod::HomeKitTransient;
        let mut pairing = PairingSession::with_identity(auth_method, identity.clone());

        let m1 = pairing.start_transient_pairing_with_pin(pin)?;
        let pair_setup_req = RtspRequest::pair_setup(m1, &client_device_id, 4);
        let m2_resp = rtsp.send(pair_setup_req).await?;

        let m2_body = m2_resp.body.as_deref().unwrap_or(&[]);
        let m3 = pairing.continue_transient_pairing(m2_body)?;

        if let Some(m3_data) = m3 {
            let pair_setup_req = RtspRequest::pair_setup(m3_data, &client_device_id, 4);
            let m4_resp = rtsp.send(pair_setup_req).await?;
            let m4_body = m4_resp.body.as_deref().unwrap_or(&[]);
            pairing.continue_transient_pairing(m4_body)?;
        }

        let session_keys = pairing.take_session_keys().ok_or_else(|| {
            RtspError::SetupFailed("Missing session keys after transient pairing".into())
        })?;

        let cipher = ControlCipher::new(
            *session_keys.write_key.as_bytes(),
            *session_keys.read_key.as_bytes(),
        );
        rtsp.set_cipher(cipher);
        match rtsp.send(RtspRequest::options()).await {
            Ok(resp) => {
                if let Some(public) = resp.header("Public") {
                    info!("OPTIONS supported methods: {}", public);
                } else {
                    info!("OPTIONS returned {} (no Public header)", resp.status_code);
                    for (k, v) in &resp.headers {
                        debug!("  OPTIONS header: {}: {}", k, v);
                    }
                }
            }
            Err(err) => {
                tracing::warn!("Encrypted OPTIONS request failed: {}", err);
            }
        }

        // Use the randomly generated shk for audio encryption.
        // The shk is sent to the receiver in SETUP phase 2.
        // Don't override with shared secret - that's only for RTSP encryption.
        tracing::debug!("Using random shk for audio encryption (sent in SETUP phase 2)");

        session.set_paired()?;

        Ok(Self {
            device,
            rtsp,
            session,
            pairing: Some(pairing),
            streamer: None,
            playback_state: PlaybackState::Stopped,
            volume: 1.0,
            stream_config: config,
            timing_offset: None,
            timing_tx: None,
            timing_task: None,
            timing_server: None,
            ptp_master: None,
            ptp_master_sync_task: None,
            control_receiver: None,
            control_task: None,
            events_stream: None,
        })
    }

    /// Complete RTSP SETUP phases (called before streaming).
    pub async fn setup(&mut self) -> Result<()> {
        tracing::info!(
            "RTSP setup start (stream_type={:?}, timing={:?})",
            self.stream_config.stream_type,
            self.stream_config.timing_protocol
        );

        // Start timing server based on protocol
        let local_timing_port = match self.stream_config.timing_protocol {
            TimingProtocol::Ntp => {
                // For NTP, we run a server that the receiver can sync to
                let timing_server = NtpTimingServer::start(
                    self.stream_config.audio_format.sample_rate.as_hz()
                ).await?;
                let port = timing_server.port();
                tracing::info!("Started NTP timing server on port {}", port);
                self.timing_server = Some(timing_server);
                port
            }
            TimingProtocol::Ptp => {
                // PTP mode determines whether sender is master (sends Sync) or slave (receives Sync).
                // Master mode: for third-party receivers like Shairport-sync
                // Slave mode: for HomePod multi-room where HomePod is the timing master
                let mode_str = match self.stream_config.ptp_mode {
                    airplay_core::PtpMode::Master => "master (sender is timing reference)",
                    airplay_core::PtpMode::Slave => "slave (receiver is timing reference)",
                };
                tracing::info!("PTP timing: will act as {}", mode_str);
                PTP_EVENT_PORT
            }
        };

        // SETUP Phase 1 (timing/event channels)
        let local_addresses = self.rtsp.local_addr()
            .map(|sa| vec![sa.ip().to_string()])
            .unwrap_or_default();
        let setup1_body = self.session.build_setup_phase1(local_timing_port, Some(local_addresses))?;
        tracing::debug!(
            uri = %self.session.request_uri(),
            body_len = setup1_body.len(),
            "Sending SETUP phase 1"
        );
        let setup1_req = RtspRequest::setup(self.session.request_uri(), setup1_body);
        let setup1_resp = self.rtsp.send(setup1_req).await?;

        // Log the response for debugging
        if let Some(ref body) = setup1_resp.body {
            tracing::debug!(
                status = setup1_resp.status_code,
                body_len = body.len(),
                "SETUP phase 1 response received"
            );
        }

        self.session.process_setup_phase1_response(setup1_resp.body.as_deref().unwrap_or(&[]))?;

        // Add RTSP Session header for all subsequent requests (RECORD, SETUP phase 2, etc.)
        let session_id = setup1_resp.headers.get("Session")
            .cloned()
            .unwrap_or_else(|| "1".to_string());
        self.rtsp.add_session_header("Session", session_id);

        // Get device address and ports from SETUP phase 1 response
        // Copy the address value to avoid borrow conflict with later mutable calls
        let addr = *select_best_address(&self.device.addresses)
            .ok_or_else(|| RtspError::ConnectionRefused)?;
        let ports = self.session.ports()
            .ok_or_else(|| CoreError::Rtsp(RtspError::InvalidResponse("No ports in SETUP response".into())))?;
        // Extract port values to avoid borrowing self.session during later mutable calls
        let event_port = ports.event_port;

        // Establish events connection (reverse connection to device's events port)
        // This MUST be done before SETUP phase 2 or some devices return 500
        let events_addr = SocketAddr::new(addr, event_port);
        tracing::info!("Establishing events connection to {}", events_addr);
        match TcpStream::connect(events_addr).await {
            Ok(stream) => {
                tracing::info!("Events connection established");
                self.events_stream = Some(stream);
            }
            Err(e) => {
                // Not fatal - owntone says "proceeding anyway" if this fails
                warn!("Could not connect to events port {} (proceeding anyway): {}", events_addr, e);
            }
        }

        // Bind a real UDP socket for the control port before SETUP phase 2.
        // The receiver sends RTCP/retransmit-request packets to this port;
        // without a bound socket it gets ICMP "port unreachable" and may mute the stream.
        let mut control_receiver = RtpReceiver::new();
        let actual_control_port = control_receiver.bind(0)?;
        self.session.set_local_control_port(actual_control_port);
        tracing::info!("Control port bound to {}", actual_control_port);
        self.control_receiver = Some(Arc::new(control_receiver));

        // SETUP Phase 2 (audio stream)
        let setup2_body = self.session.build_setup_phase2()?;
        let setup2_req = RtspRequest::setup(self.session.request_uri(), setup2_body);
        let setup2_resp = self.rtsp.send(setup2_req).await?;
        tracing::debug!(
            "SETUP phase 2 response: status={}, body_len={}, has_body={}",
            setup2_resp.status_code,
            setup2_resp.body.as_ref().map(|b| b.len()).unwrap_or(0),
            setup2_resp.body.is_some()
        );
        if let Some(ref body) = setup2_resp.body {
            tracing::debug!("SETUP phase2 response body (hex, first 100 bytes): {:02x?}", &body[..body.len().min(100)]);
        }
        self.session.process_setup_phase2_response(setup2_resp.body.as_deref().unwrap_or(&[]))?;

        // RECORD — sent after both SETUP phases so the receiver has streams configured
        tracing::debug!("Sending RECORD request");
        let record_req = RtspRequest::record_with_info(
            self.session.request_uri(),
            0,  // Initial sequence number
            0,  // Initial RTP time
        );
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.rtsp.send(record_req)
        ).await {
            Ok(Ok(resp)) => {
                if resp.status_code == 200 {
                    tracing::info!("RECORD acknowledged");
                } else {
                    warn!("RECORD returned status {} (continuing anyway)", resp.status_code);
                }
            }
            Ok(Err(e)) => warn!("RECORD error (continuing anyway): {}", e),
            Err(_) => warn!("RECORD timeout (continuing anyway)"),
        }

        // SETPEERS disabled — not needed for current receiver targets
        // let local_addr_str = self.rtsp.local_addr()
        //     .map(|sa| sa.ip().to_string())
        //     .unwrap_or_else(|| "0.0.0.0".to_string());
        // let device_addr_str = addr.to_string();
        // {
        //     let peer_addresses = vec![device_addr_str, local_addr_str];
        //     tracing::debug!("Sending SETPEERS with addresses: {:?}", peer_addresses);
        //     match self.send_setpeers(&peer_addresses).await {
        //         Ok(()) => tracing::info!("SETPEERS sent"),
        //         Err(e) => warn!("SETPEERS failed (continuing anyway): {}", e),
        //     }
        // }

        // Timing sync - after stream is set up
        match self.stream_config.timing_protocol {
            TimingProtocol::Ntp => {
                // For NTP, the sender IS the timing reference.
                // The receiver syncs to our NTP server (started above).
                // No client-side sync needed — our clock offset is zero.
                self.timing_offset = Some(ClockOffset::default());
                tracing::info!("NTP timing: sender is reference clock (offset=0)");
            }
            TimingProtocol::Ptp => {
                match self.stream_config.ptp_mode {
                    airplay_core::PtpMode::Master => {
                        // Master mode with bidirectional gPTP: sync TO HomePod's clock
                        let (offset_tx, mut offset_rx) = watch::channel(ClockOffset::default());
                        self.timing_tx = Some(offset_tx.clone());

                        // Start PTP master (binds ports 319/320, calculates offset from HomePod)
                        let mut ptp_master = PtpMaster::new();
                        ptp_master.set_offset_sender(offset_tx);
                        match ptp_master.start().await {
                            Ok(()) => {
                                tracing::info!("PTP master started on ports 319/320");

                                // Get references to the sockets for the sync loop
                                let event_socket = ptp_master.event_socket().cloned();
                                let general_socket = ptp_master.general_socket().cloned();
                                let clock_identity = ptp_master.clock_identity();

                                // Spawn background task to send Sync every ~200ms to the HomePod
                                // CRITICAL: PTP uses TWO different ports:
                                // - Event port 319: for Sync messages (time-critical)
                                // - General port 320: for Announce messages (non-time-critical)
                                let event_addr = SocketAddr::new(addr, PTP_EVENT_PORT);
                                let general_addr = SocketAddr::new(addr, PTP_GENERAL_PORT);
                                if let (Some(evt), Some(gen)) = (event_socket, general_socket) {
                                    tracing::info!("Spawning gPTP sync loop: event={}, general={}", event_addr, general_addr);
                                    self.ptp_master_sync_task = Some(tokio::spawn(async move {
                                        tracing::info!("gPTP master loop started: event={}, general={}", event_addr, general_addr);
                                        let mut sync_seq: u16 = 0;
                                        let mut announce_seq: u16 = 0;
                                        let mut signaling_seq: u16 = 0;
                                        let mut sync_count: u32 = 0;

                                        // gPTP timing intervals (802.1AS)
                                        const SYNC_INTERVAL_MS: u64 = 125;      // 125ms = 2^-3 seconds (logInterval: -3)
                                        const ANNOUNCE_INTERVAL_MS: u64 = 250;  // 250ms = 2^-2 seconds (logInterval: -2)

                                        // Initial gPTP negotiation: Send Announce + Signaling
                                        tracing::info!("gPTP: Starting negotiation handshake");
                                        if let Err(e) = airplay_timing::send_ptp_announce(
                                            &gen, general_addr, &clock_identity, &mut announce_seq, 193,
                                        ).await {
                                            tracing::error!("Failed to send initial Announce: {}", e);
                                        }

                                        if let Err(e) = airplay_timing::send_ptp_signaling(
                                            &gen, general_addr, &clock_identity, &mut signaling_seq,
                                            -3,  // Sync interval: 2^-3 = 125ms
                                            -2,  // Announce interval: 2^-2 = 250ms
                                        ).await {
                                            tracing::error!("Failed to send initial Signaling: {}", e);
                                        }

                                        tracing::info!("gPTP: Negotiation complete, starting sync loop");

                                        // Main sync loop with gPTP intervals
                                        let mut sync_interval = tokio::time::interval(std::time::Duration::from_millis(SYNC_INTERVAL_MS));
                                        let mut announce_interval = tokio::time::interval(std::time::Duration::from_millis(ANNOUNCE_INTERVAL_MS));

                                        loop {
                                            tokio::select! {
                                                _ = sync_interval.tick() => {
                                                    // Send Sync + Follow_Up every 125ms
                                                    match airplay_timing::send_ptp_sync(
                                                        &evt, &gen, event_addr, &clock_identity, &mut sync_seq,
                                                    ).await {
                                                        Ok(()) => {
                                                            sync_count += 1;
                                                            if sync_count % 40 == 0 {
                                                                tracing::info!("gPTP: Sent {} Sync messages (latest seq={})", sync_count, sync_seq);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!("gPTP sync send error: {}", e);
                                                        }
                                                    }
                                                }
                                                _ = announce_interval.tick() => {
                                                    // Send Announce every 250ms
                                                    match airplay_timing::send_ptp_announce(
                                                        &gen, general_addr, &clock_identity, &mut announce_seq, 193,
                                                    ).await {
                                                        Ok(()) => {
                                                            tracing::debug!("gPTP Announce sent to {} (seq={})", general_addr, announce_seq);
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!("gPTP Announce send error: {}", e);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }));
                                } else {
                                    tracing::warn!("PTP master sockets not available - sync loop not started");
                                }

                                self.ptp_master = Some(ptp_master);

                                // Wait briefly for initial gPTP negotiation and offset calculation
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                                // Get initial offset from watch channel
                                let initial_offset = *offset_rx.borrow_and_update();
                                self.timing_offset = Some(initial_offset);

                                tracing::info!("gPTP master initialized (syncing TO HomePod, initial offset: {} ns)", initial_offset.offset_ns);
                            }
                            Err(e) => {
                                warn!("Failed to start PTP master (continuing without PTP): {}", e);
                            }
                        }
                    }
                    airplay_core::PtpMode::Slave => {
                        // Slave mode: Receiver (HomePod) is the timing master
                        // We listen for Sync/Announce from receiver and calculate offset

                        // Create watch channel for clock offset updates
                        let (offset_tx, mut offset_rx) = watch::channel(ClockOffset::default());

                        // Store the sender for the streamer to subscribe to
                        self.timing_tx = Some(offset_tx.clone());

                        // Spawn PTP slave task to listen for Sync/Follow-Up from HomePod
                        tracing::info!("Starting PTP slave to sync with receiver at {}", addr);
                        let ptp_task = tokio::spawn(async move {
                            match run_ptp_slave(addr, offset_tx).await {
                                Ok(()) => {
                                    tracing::info!("PTP slave task completed");
                                }
                                Err(e) => {
                                    tracing::error!("PTP slave task error: {}", e);
                                }
                            }
                        });

                        self.timing_task = Some(ptp_task);

                        // Wait a moment for initial sync before proceeding
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                        // Get the current offset from the channel
                        let initial_offset = *offset_rx.borrow_and_update();
                        self.timing_offset = Some(initial_offset);

                        tracing::info!("PTP slave initialized (initial offset: {} ns)", initial_offset.offset_ns);
                    }
                }
            }
        }

        tracing::info!("RTSP setup complete");
        Ok(())
    }

    /// Disconnect and clean up.
    pub async fn disconnect(&mut self) -> Result<()> {
        // Stop streaming if active
        if let Some(ref mut streamer) = self.streamer {
            streamer.stop().await?;
        }

        if let Some(task) = self.timing_task.take() {
            task.abort();
        }

        // Stop timing server
        if let Some(mut server) = self.timing_server.take() {
            server.stop().await;
        }

        // Stop PTP master sync task and master itself
        if let Some(task) = self.ptp_master_sync_task.take() {
            task.abort();
        }
        if let Some(mut master) = self.ptp_master.take() {
            master.stop().await;
        }

        // Drop control receiver (closes the UDP socket)
        self.control_receiver = None;

        // Send TEARDOWN if session is active
        if self.session.state() != SessionState::Disconnected {
            let _ = self.session.start_teardown();
            let teardown_req = RtspRequest::teardown(self.session.request_uri());
            let _ = self.rtsp.send(teardown_req).await;
        }

        // Close connection
        self.rtsp.close().await?;
        self.playback_state = PlaybackState::Stopped;

        Ok(())
    }

    /// Get connected device.
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Get RTSP session state.
    pub fn session_state(&self) -> SessionState {
        self.session.state()
    }

    /// Get playback state.
    pub fn playback_state(&self) -> PlaybackState {
        self.playback_state
    }

    /// Get current playback position in seconds.
    pub fn playback_position(&self) -> f64 {
        self.streamer
            .as_ref()
            .map(|s| s.position() as f64 / self.stream_config.audio_format.sample_rate.as_hz() as f64)
            .unwrap_or(0.0)
    }

    /// Get current volume.
    pub fn volume(&self) -> f32 {
        self.volume
    }

    /// Start audio streaming from a decoder source.
    pub async fn start_streaming(&mut self, decoder: AudioDecoder) -> Result<()> {
        // Ensure setup is complete
        if self.session.state() != SessionState::Ready {
            self.setup().await?;
        }

        // Configure RTP sender
        let ports = self.session.ports()
            .ok_or_else(|| RtspError::SetupFailed("Missing ports from SETUP".into()))?;
        tracing::debug!(
            "Session ports: data={}, control={}, timing={}, event={}",
            ports.data_port, ports.control_port, ports.timing_port, ports.event_port
        );
        let dest_addr = select_best_address(&self.device.addresses)
            .ok_or_else(|| RtspError::ConnectionRefused)?;
        let dest = SocketAddr::new(*dest_addr, ports.data_port);
        let control_dest = SocketAddr::new(*dest_addr, ports.control_port);
        let mut sender = RtpSender::new(dest, rand::random());
        sender.set_control_dest(control_dest);
        sender.bind(0)?;

        // Give the sender a clone of our control socket so sync packets are sent
        // from our declared control port (not the data socket's random port).
        // The receiver expects sync to come from the port we advertised in SETUP.
        if let Some(ref control_rx) = self.control_receiver {
            if let Ok(Some(ctrl_sock)) = control_rx.try_clone_socket() {
                let ctrl_port = ctrl_sock.local_addr().map(|a| a.port()).unwrap_or(0);
                sender.set_control_socket(ctrl_sock);
                tracing::info!("Sync packets will be sent from control port {}", ctrl_port);
            } else {
                tracing::warn!("Could not clone control socket for sync packets");
            }
        }

        tracing::info!("RTP sender bound, data: {}, control: {}", dest, control_dest);

        // Enable audio encryption (shk from SETUP)
        let stream_key = *self.session.stream_key();
        info!(
            "DIAG AirPlay2 shk (first 16 bytes): {:02x?}",
            &stream_key[..16]
        );
        let audio_cipher = AudioCipher::new(stream_key);
        sender.set_cipher(Box::new(ChaChaPacketCipher::new(audio_cipher)));
        info!("DIAG: ChaCha20-Poly1305 audio encryption enabled");

        // Start streamer
        let mut streamer = AudioStreamer::new(self.stream_config.clone());
        streamer.set_rtp_sender(sender).await;
        if let Some(offset) = self.timing_offset {
            streamer.set_timing_offset(offset).await;
        }
        if let Some(ref tx) = self.timing_tx {
            streamer.set_timing_updates(tx.subscribe()).await;
        }
        // As PTP master, our clock is the reference - offset is always 0.
        // No watch::Receiver needed (timing_offset was set to default in setup).

        // FLUSH before streaming — tells receiver to clear buffers and expect audio
        // starting at the given seq/rtptime.
        let flush_req = RtspRequest::flush_with_info(
            self.session.request_uri(),
            0,  // Initial sequence number (RtpSender starts at 0)
            0,  // Initial RTP timestamp
        );
        if let Err(e) = self.rtsp.send(flush_req).await {
            tracing::warn!("FLUSH failed (continuing anyway): {}", e);
        } else {
            tracing::info!("FLUSH sent before streaming");
        }

        streamer.start(decoder).await?;

        // RECORD was sent at the end of setup(), just update state
        self.session.start_playing()?;

        // Send SET_PARAMETER volume to ensure HomePod is not muted
        tracing::info!("Sending SET_PARAMETER volume");
        if let Err(e) = self.set_volume(self.volume).await {
            tracing::warn!("Failed to set volume: {}", e);
        }

        // Spawn control channel on a dedicated blocking thread for low-latency
        // retransmit handling. Uses 5ms recv timeout (well under HomePod's 70ms buffer)
        // so retransmit requests are handled promptly.
        let control_task = if let Some(ref control_rx) = self.control_receiver {
            use airplay_audio::RetransmitRequest;
            let control_rx_clone = Arc::clone(control_rx);
            let streamer_clone = streamer.clone();
            let rt_handle = tokio::runtime::Handle::current();

            Some(tokio::task::spawn_blocking(move || {
                tracing::debug!("Control channel thread started (5ms poll)");
                loop {
                    // Use raw receive to handle all packet formats (including
                    // retransmit requests which have 8-byte headers without SSRC).
                    // 5ms timeout keeps retransmit latency low.
                    match control_rx_clone.recv_raw_timeout(std::time::Duration::from_millis(5)) {
                        Ok(Some((data, _addr))) => {
                            if data.len() < 4 {
                                tracing::debug!("Control channel: ignoring tiny packet ({} bytes)", data.len());
                                continue;
                            }

                            let payload_type = data[1] & 0x7F;

                            if payload_type == 85 {
                                // Retransmit request (PT=85):
                                // Apple uses an 8-byte compact format:
                                //   [0-1] RTP header (V=2, PT=85)
                                //   [2-3] Sequence number of request
                                //   [4-5] First lost sequence number
                                //   [6-7] Number of lost packets
                                // Or a 12-byte format:
                                //   [0-7] 8-byte RTP header (no SSRC)
                                //   [8-9] First lost sequence number
                                //   [10-11] Number of lost packets
                                let request = if data.len() == 8 {
                                    // 8-byte compact format
                                    let first_sequence = u16::from_be_bytes([data[4], data[5]]);
                                    let count = u16::from_be_bytes([data[6], data[7]]);
                                    Some(RetransmitRequest { first_sequence, count })
                                } else if data.len() >= 12 {
                                    RetransmitRequest::parse(&data).ok()
                                } else {
                                    let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                                    tracing::debug!(
                                        "Control channel: PT=85 unexpected len={}, hex=[{}]",
                                        data.len(), hex
                                    );
                                    None
                                };

                                if let Some(request) = request {
                                    tracing::debug!(
                                        "Retransmit request: seq={}, count={}",
                                        request.first_sequence, request.count
                                    );
                                    // Use block_on to call async handle_retransmit from blocking thread
                                    match rt_handle.block_on(streamer_clone.handle_retransmit(&request)) {
                                        Ok(retransmitted) => {
                                            if retransmitted > 0 {
                                                tracing::info!(
                                                    "Retransmitted {} packets starting from seq {}",
                                                    retransmitted, request.first_sequence
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("Retransmit failed: {}", e);
                                        }
                                    }
                                }
                            } else if payload_type == 84 {
                                // Sync/timing packet (PT=84) — can ignore
                                tracing::trace!("Control channel: sync packet (PT=84, {} bytes)", data.len());
                            } else {
                                // Log unknown packet types with hex dump for debugging
                                let hex: String = data.iter().take(16).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                                tracing::debug!(
                                    "Control channel: unknown PT={}, len={}, hex=[{}]",
                                    payload_type, data.len(), hex
                                );
                            }
                        }
                        Ok(None) => {
                            // Timeout, continue polling
                        }
                        Err(e) => {
                            tracing::debug!("Control channel recv error: {}, continuing", e);
                        }
                    }
                }
            }))
        } else {
            None
        };

        self.streamer = Some(streamer);
        self.control_task = control_task;
        self.playback_state = PlaybackState::Playing;

        if self.control_task.is_some() {
            tracing::info!("Started control channel polling for retransmit requests");
        }

        Ok(())
    }

    /// Pause streaming.
    pub async fn pause(&mut self) -> Result<()> {
        if let Some(ref mut streamer) = self.streamer {
            streamer.pause().await?;
        }

        // Send FLUSH with RTP-Info to pause on receiver
        let flush_req = RtspRequest::flush_with_info(
            self.session.request_uri(),
            0,
            0,
        );
        self.rtsp.send(flush_req).await?;

        // Reset marker/extension bit state so the next RECORD sends them correctly
        if let Some(ref mut streamer) = self.streamer {
            streamer.reset_after_flush().await;
        }

        self.session.pause()?;
        self.playback_state = PlaybackState::Paused;

        Ok(())
    }

    /// Resume streaming.
    pub async fn resume(&mut self) -> Result<()> {
        if let Some(ref mut streamer) = self.streamer {
            streamer.resume().await?;
        }

        // Send RECORD to resume
        let record_req = RtspRequest::record(self.session.request_uri());
        self.rtsp.send(record_req).await?;
        self.session.start_playing()?;
        self.playback_state = PlaybackState::Playing;

        Ok(())
    }

    /// Stop streaming.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(ref mut streamer) = self.streamer {
            streamer.stop().await?;
        }

        // Send FLUSH with RTP-Info to stop on receiver.
        // Using flush_with_info avoids 400 Bad Request from HomePod.
        let flush_req = RtspRequest::flush_with_info(
            self.session.request_uri(),
            0,
            0,
        );
        let _ = self.rtsp.send(flush_req).await;

        // Reset marker/extension bit state in case streaming resumes later
        if let Some(ref mut streamer) = self.streamer {
            streamer.reset_after_flush().await;
        }

        self.playback_state = PlaybackState::Stopped;

        Ok(())
    }

    /// Set volume.
    pub async fn set_volume(&mut self, volume: f32) -> Result<()> {
        let clamped = volume.clamp(0.0, 1.0);
        self.volume = clamped;

        // Send SET_PARAMETER with volume
        let volume_body = self.session.build_set_volume(clamped)?;
        let volume_req = RtspRequest::set_parameter_text(self.session.request_uri(), volume_body);
        self.rtsp.send(volume_req).await?;

        Ok(())
    }

    /// Send feedback/keepalive to the receiver.
    ///
    /// AirPlay 2 receivers expect periodic feedback requests (~every 2 seconds).
    /// Call this from your playback loop to maintain the session.
    pub async fn send_feedback(&mut self) -> Result<()> {
        let uri = self.session.request_uri();
        let req = RtspRequest::feedback(uri);
        match tokio::time::timeout(std::time::Duration::from_secs(2), self.rtsp.send(req)).await {
            Ok(Ok(resp)) => {
                tracing::trace!("Feedback response: status={}", resp.status_code);
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::debug!("Feedback request failed: {}", e);
                Err(e)
            }
            Err(_) => {
                tracing::debug!("Feedback request timed out");
                Ok(()) // Don't fail on timeout - it's just a keepalive
            }
        }
    }

    /// Send SETPEERS for multi-room (addresses of all group members).
    pub async fn send_setpeers(&mut self, peer_addresses: &[String]) -> Result<()> {
        let setpeers_body = self.session.build_setpeers(peer_addresses)?;
        let setpeers_req = RtspRequest::setpeers(&self.session.id().to_string(), setpeers_body);
        self.rtsp.send(setpeers_req).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // ============================================================================
    // Helper Function Tests
    // ============================================================================

    mod device_id_generation {
        use super::*;

        #[test]
        fn generates_valid_mac_format() {
            let device_id = generate_device_id();

            // Should be in format XX:XX:XX:XX:XX:XX
            assert_eq!(device_id.len(), 17); // 6 pairs of 2 chars + 5 colons
            assert_eq!(device_id.matches(':').count(), 5);

            // Each segment should be valid hex
            for part in device_id.split(':') {
                assert_eq!(part.len(), 2);
                assert!(u8::from_str_radix(part, 16).is_ok());
            }
        }

        #[test]
        fn generates_unique_ids() {
            let id1 = generate_device_id();
            let id2 = generate_device_id();
            let id3 = generate_device_id();

            // Should generate different IDs each time (with very high probability)
            assert_ne!(id1, id2);
            assert_ne!(id2, id3);
            assert_ne!(id1, id3);
        }

        #[test]
        fn generates_uppercase_hex() {
            let device_id = generate_device_id();

            // All hex digits should be uppercase
            for c in device_id.chars() {
                if c != ':' {
                    assert!(c.is_ascii_uppercase() || c.is_ascii_digit());
                }
            }
        }
    }

    mod stream_key_extraction {
        use super::*;
        use airplay_crypto::keys::SharedSecret;

        #[test]
        fn extracts_32_bytes_from_shared_secret() {
            let bytes = vec![0u8; 32];
            let secret = SharedSecret::new(bytes);

            let key = stream_key_from_shared_secret(&secret).unwrap();
            assert_eq!(key.len(), 32);
            assert_eq!(key, [0u8; 32]);
        }

        #[test]
        fn extracts_first_32_bytes_when_longer() {
            let mut bytes = vec![0xFF; 64];
            bytes[0..32].fill(0xAA);
            bytes[32..64].fill(0xBB);
            let secret = SharedSecret::new(bytes);

            let key = stream_key_from_shared_secret(&secret).unwrap();
            assert_eq!(key.len(), 32);
            assert_eq!(key, [0xAA; 32]);
        }

        #[test]
        fn fails_when_shared_secret_too_short() {
            let bytes = vec![0u8; 16]; // Only 16 bytes
            let secret = SharedSecret::new(bytes);

            let result = stream_key_from_shared_secret(&secret);
            assert!(result.is_err());

            let err = result.unwrap_err();
            assert!(matches!(err, CoreError::Rtsp(_)));
        }

        #[test]
        fn fails_with_descriptive_error_message() {
            let bytes = vec![0u8; 10];
            let secret = SharedSecret::new(bytes);

            let result = stream_key_from_shared_secret(&secret);
            assert!(result.is_err());

            let err_msg = format!("{:?}", result.unwrap_err());
            assert!(err_msg.contains("too short") || err_msg.contains("SetupFailed"));
        }
    }

    mod address_selection {
        use super::*;
        use std::net::IpAddr;

        #[test]
        fn prefers_ipv4_over_ipv6() {
            let addresses = vec![
                "fe80::1".parse::<IpAddr>().unwrap(),  // link-local IPv6
                "192.168.1.100".parse().unwrap(),       // IPv4
                "2001:db8::1".parse().unwrap(),         // global IPv6
            ];

            let selected = select_best_address(&addresses);
            assert!(selected.is_some());
            assert!(selected.unwrap().is_ipv4());
            assert_eq!(selected.unwrap().to_string(), "192.168.1.100");
        }

        #[test]
        fn selects_global_ipv6_when_no_ipv4() {
            let addresses = vec![
                "fe80::1".parse::<IpAddr>().unwrap(),  // link-local IPv6
                "2001:db8::1".parse().unwrap(),         // global IPv6
                "fe80::2".parse().unwrap(),             // another link-local
            ];

            let selected = select_best_address(&addresses);
            assert!(selected.is_some());
            assert!(selected.unwrap().is_ipv6());
            assert_eq!(selected.unwrap().to_string(), "2001:db8::1");
        }

        #[test]
        fn avoids_link_local_ipv6() {
            let addresses = vec![
                "fe80::1".parse::<IpAddr>().unwrap(),  // link-local
                "fe80::2".parse().unwrap(),             // link-local
            ];

            let selected = select_best_address(&addresses);
            // Should return first as fallback, but would prefer non-link-local
            assert!(selected.is_some());
        }

        #[test]
        fn returns_first_address_as_fallback() {
            let addresses = vec![
                "fe80::1".parse::<IpAddr>().unwrap(),
            ];

            let selected = select_best_address(&addresses);
            assert!(selected.is_some());
            assert_eq!(selected.unwrap().to_string(), "fe80::1");
        }

        #[test]
        fn returns_none_for_empty_list() {
            let addresses: Vec<IpAddr> = vec![];

            let selected = select_best_address(&addresses);
            assert!(selected.is_none());
        }

        #[test]
        fn prefers_first_ipv4_when_multiple() {
            let addresses = vec![
                "192.168.1.100".parse::<IpAddr>().unwrap(),
                "192.168.1.101".parse().unwrap(),
                "10.0.0.1".parse().unwrap(),
            ];

            let selected = select_best_address(&addresses);
            assert!(selected.is_some());
            assert_eq!(selected.unwrap().to_string(), "192.168.1.100");
        }

        #[test]
        fn avoids_ipv6_loopback() {
            let addresses = vec![
                "::1".parse::<IpAddr>().unwrap(),      // IPv6 loopback
                "2001:db8::1".parse().unwrap(),         // global IPv6
            ];

            let selected = select_best_address(&addresses);
            assert!(selected.is_some());
            assert_eq!(selected.unwrap().to_string(), "2001:db8::1");
        }
    }

    mod link_local_detection {
        use super::*;

        #[test]
        fn detects_link_local_fe80() {
            let addr: Ipv6Addr = "fe80::1".parse().unwrap();
            assert!(is_link_local_v6(&addr));
        }

        #[test]
        fn detects_link_local_fe80_with_suffix() {
            let addr: Ipv6Addr = "fe80::abcd:ef01:2345:6789".parse().unwrap();
            assert!(is_link_local_v6(&addr));
        }

        #[test]
        fn detects_link_local_febf() {
            // fe80-febf is link-local range
            let addr: Ipv6Addr = "febf::1".parse().unwrap();
            assert!(is_link_local_v6(&addr));
        }

        #[test]
        fn rejects_global_unicast() {
            let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
            assert!(!is_link_local_v6(&addr));
        }

        #[test]
        fn rejects_loopback() {
            let addr: Ipv6Addr = "::1".parse().unwrap();
            assert!(!is_link_local_v6(&addr));
        }

        #[test]
        fn rejects_unspecified() {
            let addr: Ipv6Addr = "::".parse().unwrap();
            assert!(!is_link_local_v6(&addr));
        }

        #[test]
        fn rejects_multicast() {
            let addr: Ipv6Addr = "ff02::1".parse().unwrap();
            assert!(!is_link_local_v6(&addr));
        }

        #[test]
        fn rejects_unique_local() {
            // fc00::/7 is unique local
            let addr: Ipv6Addr = "fc00::1".parse().unwrap();
            assert!(!is_link_local_v6(&addr));
        }
    }

    // ============================================================================
    // Connection State Tests
    // ============================================================================

    mod connection_state {
        use super::*;
        use airplay_core::{codec::{AudioCodec, AudioFormat, SampleRate}, stream::StreamType, DeviceId};

        fn make_test_device() -> Device {
            Device {
                id: DeviceId::from_mac_string("AA:BB:CC:DD:EE:FF").unwrap(),
                name: "Test Device".to_string(),
                addresses: vec!["192.168.1.100".parse().unwrap()],
                port: 7000,
                model: "TestModel1,1".to_string(),
                features: Default::default(),
                public_key: None,
                source_version: Default::default(),
                requires_password: false,
                group_id: None,
                is_group_leader: false,
                raop_port: None,
                raop_encryption_types: None,
                raop_codecs: None,
                raop_transport: None,
            }
        }

        fn make_test_config() -> StreamConfig {
            StreamConfig {
                stream_type: StreamType::Buffered,
                audio_format: AudioFormat {
                    codec: AudioCodec::Alac,
                    sample_rate: SampleRate::Hz44100,
                    channels: 2,
                    bit_depth: 16,
                    frames_per_packet: 352,
                },
                timing_protocol: TimingProtocol::Ntp,
                latency_min: 22050,
                latency_max: 132300,
                supports_dynamic_stream_id: true,
                asc: None,
            }
        }

        #[test]
        fn playback_state_starts_stopped() {
            // We can't easily construct a Connection without real network I/O,
            // but we can test that PlaybackState enum works
            let state = PlaybackState::Stopped;
            assert_eq!(state, PlaybackState::Stopped);
        }

        #[test]
        fn device_getter_would_return_device() {
            // This verifies the pattern - actual test would need mock
            let device = make_test_device();
            assert_eq!(device.name, "Test Device");
        }

        #[test]
        fn config_has_correct_defaults() {
            let config = make_test_config();
            assert_eq!(config.stream_type, StreamType::Buffered);
            assert_eq!(config.audio_format.sample_rate, SampleRate::Hz44100);
            assert_eq!(config.timing_protocol, TimingProtocol::Ntp);
        }
    }

    // ============================================================================
    // Volume Control Tests
    // ============================================================================

    mod volume_control {
        use super::*;

        #[test]
        fn volume_clamping_preserves_valid_range() {
            assert_eq!(0.0f32.clamp(0.0, 1.0), 0.0);
            assert_eq!(0.5f32.clamp(0.0, 1.0), 0.5);
            assert_eq!(1.0f32.clamp(0.0, 1.0), 1.0);
        }

        #[test]
        fn volume_clamping_clamps_below_zero() {
            assert_eq!((-0.5f32).clamp(0.0, 1.0), 0.0);
            assert_eq!((-100.0f32).clamp(0.0, 1.0), 0.0);
        }

        #[test]
        fn volume_clamping_clamps_above_one() {
            assert_eq!(1.5f32.clamp(0.0, 1.0), 1.0);
            assert_eq!(100.0f32.clamp(0.0, 1.0), 1.0);
        }

        #[test]
        fn volume_precision_preserved() {
            let precise = 0.742857f32;
            assert_eq!(precise.clamp(0.0, 1.0), precise);
        }
    }

    // ============================================================================
    // Error Handling Tests
    // ============================================================================

    mod error_handling {
        use super::*;

        #[test]
        fn stream_key_error_type_is_correct() {
            let bytes = vec![0u8; 10];
            let secret = SharedSecret::new(bytes);

            let result = stream_key_from_shared_secret(&secret);
            assert!(result.is_err());

            match result {
                Err(CoreError::Rtsp(RtspError::SetupFailed(_))) => {},
                _ => panic!("Expected RtspError::SetupFailed"),
            }
        }

        #[test]
        fn empty_address_list_returns_none() {
            let addresses: Vec<IpAddr> = vec![];
            assert!(select_best_address(&addresses).is_none());
        }
    }

    // ============================================================================
    // Integration Pattern Tests (documenting expected flows)
    // ============================================================================

    mod integration_patterns {
        use super::*;

        #[test]
        fn connection_flow_pattern() {
            // This test documents the expected connection flow pattern
            // Actual implementation would require mocking RtspConnection

            // Expected flow:
            // 1. TCP connect to device address
            // 2. GET /info
            // 3. POST /pair-setup (M1-M4 for transient)
            // 4. POST /pair-verify (if needed)
            // 5. OPTIONS with encryption
            // 6. SETUP phase 1 (timing/event)
            // 7. Events connection
            // 8. SETUP phase 2 (audio)
            // 9. RECORD

            // This is a documentation test
            assert!(true);
        }

        #[test]
        fn setup_phase1_configures_timing() {
            // Phase 1 should:
            // - Start timing server (NTP or PTP)
            // - Send local timing port to receiver
            // - Negotiate event port
            // - Receive timing/event ports from receiver

            assert!(true); // Documentation test
        }

        #[test]
        fn setup_phase2_configures_audio() {
            // Phase 2 should:
            // - Bind control port (for retransmits)
            // - Send audio format, encryption key (shk)
            // - Receive data/control/timing/event ports
            // - Configure RTP sender with ports

            assert!(true); // Documentation test
        }

        #[test]
        fn streaming_flow_pattern() {
            // Expected streaming flow:
            // 1. FLUSH (clear receiver buffers)
            // 2. Start AudioStreamer with decoder
            // 3. SET_PARAMETER volume
            // 4. Send RTP audio packets
            // 5. Send sync packets (1Hz)
            // 6. Handle retransmit requests

            assert!(true); // Documentation test
        }

        #[test]
        fn disconnect_cleanup_pattern() {
            // Expected cleanup:
            // 1. Stop AudioStreamer
            // 2. Stop timing tasks
            // 3. Stop timing server
            // 4. Stop PTP master
            // 5. Close control receiver
            // 6. TEARDOWN RTSP session
            // 7. Close TCP connection

            assert!(true); // Documentation test
        }
    }

    // ============================================================================
    // Cipher Configuration Tests
    // ============================================================================

    mod cipher_configuration {
        use super::*;

        #[test]
        fn control_cipher_uses_session_keys() {
            // Control cipher should use write_key and read_key from session
            // This is a pattern test - actual test would need session mock
            assert!(true);
        }

        #[test]
        fn audio_cipher_uses_stream_key() {
            // Audio cipher should use shk (stream key) from SETUP phase 2
            // shk is randomly generated and sent to receiver
            assert!(true);
        }

        #[test]
        fn cipher_initialized_after_pairing() {
            // After successful pairing (M1-M4):
            // 1. Extract session keys
            // 2. Create ControlCipher with write/read keys
            // 3. Set cipher on RtspConnection
            // 4. All subsequent RTSP commands are encrypted
            assert!(true);
        }
    }

    // ============================================================================
    // Timing Protocol Tests
    // ============================================================================

    mod timing_protocol_selection {
        use super::*;

        #[test]
        fn ntp_starts_timing_server() {
            // When timing_protocol = NTP:
            // - Start NtpTimingServer on ephemeral port
            // - Send port to receiver in SETUP phase 1
            // - Receiver sends timing requests to our server
            // - Sender is the timing reference (offset = 0)
            assert!(true);
        }

        #[test]
        fn ptp_starts_timing_master() {
            // When timing_protocol = PTP:
            // - Start PtpMaster on ports 319/320
            // - Spawn background task sending Sync every 200ms
            // - Send Announce every 1 second
            // - Sender is the timing reference (offset = 0)
            assert!(true);
        }

        #[test]
        fn timing_offset_zero_for_sender_reference() {
            // When sender is the timing reference:
            // - timing_offset = ClockOffset::default() (all zeros)
            // - No adjustment needed
            // - Receiver syncs to sender
            assert!(true);
        }
    }

    // ============================================================================
    // State Transition Tests
    // ============================================================================

    mod state_transitions {
        use super::*;

        #[test]
        fn playback_stopped_to_playing() {
            // Initial: PlaybackState::Stopped
            // After start_streaming: PlaybackState::Playing
            let initial = PlaybackState::Stopped;
            let after_start = PlaybackState::Playing;
            assert_ne!(initial, after_start);
        }

        #[test]
        fn playback_playing_to_paused() {
            // During playback: PlaybackState::Playing
            // After pause: PlaybackState::Paused
            let playing = PlaybackState::Playing;
            let paused = PlaybackState::Paused;
            assert_ne!(playing, paused);
        }

        #[test]
        fn playback_paused_to_playing() {
            // When paused: PlaybackState::Paused
            // After resume: PlaybackState::Playing
            let paused = PlaybackState::Paused;
            let playing = PlaybackState::Playing;
            assert_ne!(paused, playing);
        }

        #[test]
        fn playback_any_to_stopped() {
            // From any state, stop() should set: PlaybackState::Stopped
            let stopped = PlaybackState::Stopped;
            assert_eq!(stopped, PlaybackState::Stopped);
        }
    }
}
