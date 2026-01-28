//! PTP (IEEE 1588) timing for AirPlay 2.
//!
//! Uses UDP ports 319 (event) and 320 (general).
//! Provides sub-millisecond synchronization for multi-room audio.

use airplay_core::error::{Error, Result};
use async_trait::async_trait;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use crate::{Clock, ClockOffset, TimingProtocol};

/// PTP event port (IEEE 1588).
pub const PTP_EVENT_PORT: u16 = 319;

/// PTP general port (IEEE 1588).
pub const PTP_GENERAL_PORT: u16 = 320;

/// PTP message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PtpMessageType {
    Sync = 0x00,
    DelayReq = 0x01,
    FollowUp = 0x08,
    DelayResp = 0x09,
    Announce = 0x0B,
    Signaling = 0x0C,  // gPTP (802.1AS) signaling
}

impl PtpMessageType {
    /// Parse from byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b & 0x0F {
            0x00 => Some(Self::Sync),
            0x01 => Some(Self::DelayReq),
            0x08 => Some(Self::FollowUp),
            0x09 => Some(Self::DelayResp),
            0x0B => Some(Self::Announce),
            0x0C => Some(Self::Signaling),
            _ => None,
        }
    }
}

// ============================================================================
// TLV (Type-Length-Value) Support for gPTP (802.1AS)
// ============================================================================

/// TLV Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TlvType {
    /// Organization extension TLV (used for 802.1AS and Apple extensions)
    OrganizationExtension = 0x0003,
}

/// Organization IDs for TLVs
pub mod org_id {
    /// 802.1AS (gPTP) organization ID
    pub const GPTP: [u8; 3] = [0x00, 0x80, 0xC2];
    /// Apple Inc. organization ID
    pub const APPLE: [u8; 3] = [0x00, 0x0D, 0x93];
}

/// 802.1AS organization subtypes
pub mod gptp_subtype {
    /// Follow-Up Information TLV (in Follow_Up messages)
    pub const FOLLOW_UP_INFO: [u8; 3] = [0x00, 0x00, 0x01];
    /// Message Interval Request TLV (in Signaling messages)
    pub const MESSAGE_INTERVAL_REQUEST: [u8; 3] = [0x00, 0x00, 0x02];
}

/// Apple proprietary subtypes (observed in pcap)
pub mod apple_subtype {
    pub const TYPE_01: [u8; 3] = [0x00, 0x00, 0x01];
    pub const TYPE_04: [u8; 3] = [0x00, 0x00, 0x04];
    pub const TYPE_05: [u8; 3] = [0x00, 0x00, 0x05];
}

/// Base TLV header (4 bytes: type + length)
#[derive(Debug, Clone)]
pub struct TlvHeader {
    pub tlv_type: u16,
    pub length: u16,
}

impl TlvHeader {
    pub fn serialize(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&self.tlv_type.to_be_bytes());
        buf[2..4].copy_from_slice(&self.length.to_be_bytes());
        buf
    }
}

/// Follow-Up Information TLV (802.1AS-2011 Section 10.6.4.4.3)
/// Sent in Follow_Up messages to provide rate ratio and timing metadata
#[derive(Debug, Clone)]
pub struct FollowUpInformationTlv {
    /// Organization ID (0x0080C2 for 802.1AS)
    pub organization_id: [u8; 3],
    /// Organization subtype (0x000001 for Follow-Up Info)
    pub organization_subtype: [u8; 3],
    /// Cumulative rate offset scaled by 2^41
    pub cumulative_scaled_rate_offset: i32,
    /// GM time base indicator
    pub gm_time_base_indicator: u16,
    /// Last GM phase change (12 bytes)
    pub last_gm_phase_change: [u8; 12],
    /// Scaled last GM frequency change
    pub scaled_last_gm_freq_change: i32,
}

impl FollowUpInformationTlv {
    pub fn new() -> Self {
        Self {
            organization_id: org_id::GPTP,
            organization_subtype: gptp_subtype::FOLLOW_UP_INFO,
            cumulative_scaled_rate_offset: 0,
            gm_time_base_indicator: 0,
            last_gm_phase_change: [0; 12],
            scaled_last_gm_freq_change: 0,
        }
    }

    /// Serialize to bytes (4-byte header + 28-byte payload)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);

        // TLV header
        let header = TlvHeader {
            tlv_type: TlvType::OrganizationExtension as u16,
            length: 28,  // Payload length
        };
        buf.extend_from_slice(&header.serialize());

        // Payload
        buf.extend_from_slice(&self.organization_id);
        buf.extend_from_slice(&self.organization_subtype);
        buf.extend_from_slice(&self.cumulative_scaled_rate_offset.to_be_bytes());
        buf.extend_from_slice(&self.gm_time_base_indicator.to_be_bytes());
        buf.extend_from_slice(&self.last_gm_phase_change);
        buf.extend_from_slice(&self.scaled_last_gm_freq_change.to_be_bytes());

        buf
    }
}

/// Message Interval Request TLV (802.1AS-2011 Section 10.6.4.3.1)
/// Sent in Signaling messages to negotiate timing intervals
#[derive(Debug, Clone)]
pub struct MessageIntervalRequestTlv {
    /// Organization ID (0x0080C2 for 802.1AS)
    pub organization_id: [u8; 3],
    /// Organization subtype (0x000002 for Message Interval Request)
    pub organization_subtype: [u8; 3],
    /// Link delay interval (log base 2)
    pub link_delay_interval: i8,
    /// Time sync interval (log base 2)
    pub time_sync_interval: i8,
    /// Announce interval (log base 2)
    pub announce_interval: i8,
    /// Flags (bit 1: computeNeighborRateRatio)
    pub flags: u8,
}

impl MessageIntervalRequestTlv {
    pub fn new(sync_interval: i8, announce_interval: i8) -> Self {
        Self {
            organization_id: org_id::GPTP,
            organization_subtype: gptp_subtype::MESSAGE_INTERVAL_REQUEST,
            link_delay_interval: sync_interval,  // Use same as sync for now
            time_sync_interval: sync_interval,
            announce_interval,
            flags: 0x02,  // computeNeighborRateRatio bit set
        }
    }

    /// Serialize to bytes (4-byte header + 10-byte payload)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(14);

        // TLV header
        let header = TlvHeader {
            tlv_type: TlvType::OrganizationExtension as u16,
            length: 10,  // Payload length
        };
        buf.extend_from_slice(&header.serialize());

        // Payload
        buf.extend_from_slice(&self.organization_id);
        buf.extend_from_slice(&self.organization_subtype);
        buf.push(self.link_delay_interval as u8);
        buf.push(self.time_sync_interval as u8);
        buf.push(self.announce_interval as u8);
        buf.push(self.flags);

        buf
    }
}

/// Apple proprietary TLV (observed in pcap, exact format TBD)
/// These appear in Follow_Up and Signaling messages
#[derive(Debug, Clone)]
pub struct AppleTlv {
    /// Organization ID (0x000D93 for Apple)
    pub organization_id: [u8; 3],
    /// Organization subtype (0x01, 0x04, or 0x05)
    pub organization_subtype: [u8; 3],
    /// Variable-length payload (Apple-specific metadata)
    pub payload: Vec<u8>,
}

impl AppleTlv {
    pub fn new(subtype: [u8; 3], payload: Vec<u8>) -> Self {
        Self {
            organization_id: org_id::APPLE,
            organization_subtype: subtype,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // TLV header
        let header = TlvHeader {
            tlv_type: TlvType::OrganizationExtension as u16,
            length: (6 + self.payload.len()) as u16,
        };
        buf.extend_from_slice(&header.serialize());

        // Payload
        buf.extend_from_slice(&self.organization_id);
        buf.extend_from_slice(&self.organization_subtype);
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Parse AppleTlv from TLV data (assumes TLV type/length already parsed)
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AppleTlv too short",
            ).into());
        }

        let mut organization_id = [0u8; 3];
        organization_id.copy_from_slice(&data[0..3]);

        let mut organization_subtype = [0u8; 3];
        organization_subtype.copy_from_slice(&data[3..6]);

        let payload = data[6..].to_vec();

        Ok(Self {
            organization_id,
            organization_subtype,
            payload,
        })
    }
}

/// PTP timestamp (10 bytes: 6 bytes seconds + 4 bytes nanoseconds).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PtpTimestamp {
    /// Seconds (48-bit, upper 16 bits of u64 unused).
    pub seconds: u64,
    /// Nanoseconds (32-bit).
    pub nanoseconds: u32,
}

impl PtpTimestamp {
    /// Create timestamp for current time.
    pub fn now() -> Self {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self::from_nanos(ns)
    }

    /// Create from nanoseconds since epoch.
    pub fn from_nanos(nanos: u128) -> Self {
        Self {
            seconds: (nanos / 1_000_000_000) as u64,
            nanoseconds: (nanos % 1_000_000_000) as u32,
        }
    }

    /// Convert to nanoseconds since epoch.
    pub fn to_nanos(&self) -> u128 {
        (self.seconds as u128) * 1_000_000_000 + (self.nanoseconds as u128)
    }

    /// Serialize to 10 bytes (48-bit seconds BE + 32-bit nanos BE).
    pub fn serialize(&self) -> [u8; 10] {
        let mut buf = [0u8; 10];
        // 48-bit seconds (6 bytes, big-endian) - take lower 48 bits
        let sec_bytes = self.seconds.to_be_bytes();
        buf[0..6].copy_from_slice(&sec_bytes[2..8]);
        // 32-bit nanoseconds
        buf[6..10].copy_from_slice(&self.nanoseconds.to_be_bytes());
        buf
    }

    /// Parse from 10 bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 10 {
            return Err(Error::Parse(
                airplay_core::error::ParseError::InvalidFormat(
                    "PTP timestamp too short".into()
                )
            ));
        }

        let mut sec_bytes = [0u8; 8];
        sec_bytes[2..8].copy_from_slice(&data[0..6]);
        let seconds = u64::from_be_bytes(sec_bytes);

        let nanoseconds = u32::from_be_bytes(data[6..10].try_into().unwrap());

        Ok(Self { seconds, nanoseconds })
    }
}

/// PTP header (34 bytes).
#[derive(Debug, Clone)]
pub struct PtpHeader {
    pub message_type: PtpMessageType,
    pub version: u8,
    pub message_length: u16,
    pub domain_number: u8,
    pub flags: u16,
    pub correction_field: i64,
    pub source_port_identity: [u8; 10],
    pub sequence_id: u16,
    pub control_field: u8,
    pub log_message_interval: i8,
}

impl PtpHeader {
    /// Create new header for message type.
    pub fn new(message_type: PtpMessageType, sequence_id: u16) -> Self {
        Self {
            message_type,
            version: 2,
            message_length: 44, // Header (34) + timestamp (10)
            domain_number: 0,
            flags: 0,
            correction_field: 0,
            source_port_identity: [0; 10],
            sequence_id,
            control_field: match message_type {
                PtpMessageType::Sync => 0,
                PtpMessageType::DelayReq => 1,
                PtpMessageType::FollowUp => 2,
                PtpMessageType::DelayResp => 3,
                PtpMessageType::Announce => 5,
                PtpMessageType::Signaling => 5,  // gPTP uses 5 for Signaling
            },
            log_message_interval: 0,
        }
    }

    /// Serialize to 34 bytes.
    pub fn serialize(&self) -> [u8; 34] {
        let mut buf = [0u8; 34];

        buf[0] = self.message_type as u8;
        buf[1] = self.version;
        buf[2..4].copy_from_slice(&self.message_length.to_be_bytes());
        buf[4] = self.domain_number;
        buf[5] = 0; // Reserved
        buf[6..8].copy_from_slice(&self.flags.to_be_bytes());
        buf[8..16].copy_from_slice(&self.correction_field.to_be_bytes());
        buf[16..20].fill(0); // Reserved
        buf[20..30].copy_from_slice(&self.source_port_identity);
        buf[30..32].copy_from_slice(&self.sequence_id.to_be_bytes());
        buf[32] = self.control_field;
        buf[33] = self.log_message_interval as u8;

        buf
    }

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 34 {
            return Err(Error::Parse(
                airplay_core::error::ParseError::InvalidFormat(
                    "PTP header too short".into()
                )
            ));
        }

        let message_type = PtpMessageType::from_byte(data[0])
            .ok_or_else(|| Error::Parse(
                airplay_core::error::ParseError::InvalidFormat(
                    format!("Unknown PTP message type: {}", data[0] & 0x0F)
                )
            ))?;

        Ok(Self {
            message_type,
            version: data[1] & 0x0F,
            message_length: u16::from_be_bytes([data[2], data[3]]),
            domain_number: data[4],
            flags: u16::from_be_bytes([data[6], data[7]]),
            correction_field: i64::from_be_bytes(data[8..16].try_into().unwrap()),
            source_port_identity: data[20..30].try_into().unwrap(),
            sequence_id: u16::from_be_bytes([data[30], data[31]]),
            control_field: data[32],
            log_message_interval: data[33] as i8,
        })
    }
}

/// PTP client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtpState {
    /// Not synchronized.
    Unsynchronized,
    /// Synchronizing.
    Synchronizing,
    /// Synchronized with master.
    Synchronized,
}

/// PTP client for AirPlay 2.
pub struct PtpClient {
    master_addr: SocketAddr,
    state: PtpState,
    event_socket: Option<UdpSocket>,
    general_socket: Option<UdpSocket>,
    clock: Clock,
    sequence_id: u16,

    // Timing state for offset calculation
    t1: Option<PtpTimestamp>, // Sync send time (from Follow_Up)
    t2: Option<PtpTimestamp>, // Sync receive time (local)
    t3: Option<PtpTimestamp>, // Delay_Req send time (local)
    t4: Option<PtpTimestamp>, // Delay_Req receive time (from Delay_Resp)

    offset: ClockOffset,
}

impl PtpClient {
    /// Create new PTP client.
    pub fn new(master_addr: SocketAddr, sample_rate: u32) -> Self {
        Self {
            master_addr,
            state: PtpState::Unsynchronized,
            event_socket: None,
            general_socket: None,
            clock: Clock::new(sample_rate),
            sequence_id: 0,
            t1: None,
            t2: None,
            t3: None,
            t4: None,
            offset: ClockOffset::default(),
        }
    }

    /// Bind to PTP ports.
    pub fn bind(&mut self) -> Result<()> {
        // Event port 319 (privileged) - try it, fallback to any port
        let event = UdpSocket::bind(("0.0.0.0", PTP_EVENT_PORT))
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"))?;
        event.set_read_timeout(Some(Duration::from_secs(1)))?;

        // General port 320 (privileged) - try it, fallback to any port
        let general = UdpSocket::bind(("0.0.0.0", PTP_GENERAL_PORT))
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"))?;
        general.set_read_timeout(Some(Duration::from_secs(1)))?;

        self.event_socket = Some(event);
        self.general_socket = Some(general);

        Ok(())
    }

    /// Process received Sync message.
    pub fn process_sync(&mut self, _header: &PtpHeader) {
        // Record receive time
        self.t2 = Some(PtpTimestamp::now());
        self.state = PtpState::Synchronizing;
    }

    /// Process received Follow_Up message.
    pub fn process_follow_up(&mut self, _header: &PtpHeader, data: &[u8]) -> Result<()> {
        // Extract precise origin timestamp from Follow_Up
        if data.len() >= 44 {
            self.t1 = Some(PtpTimestamp::parse(&data[34..44])?);
        }
        Ok(())
    }

    /// Send Delay_Req message.
    pub fn send_delay_req(&mut self) -> Result<()> {
        let socket = self.event_socket.as_ref()
            .ok_or_else(|| Error::Rtsp(
                airplay_core::error::RtspError::NoSession
            ))?;

        self.sequence_id = self.sequence_id.wrapping_add(1);
        let header = PtpHeader::new(PtpMessageType::DelayReq, self.sequence_id);

        // Record send time
        self.t3 = Some(PtpTimestamp::now());

        let mut packet = [0u8; 44];
        packet[..34].copy_from_slice(&header.serialize());
        packet[34..44].copy_from_slice(&self.t3.unwrap().serialize());

        let dest = SocketAddr::new(self.master_addr.ip(), PTP_EVENT_PORT);
        socket.send_to(&packet, dest)?;

        Ok(())
    }

    /// Process Delay_Resp message.
    pub fn process_delay_resp(&mut self, _header: &PtpHeader, data: &[u8]) -> Result<()> {
        if data.len() >= 44 {
            self.t4 = Some(PtpTimestamp::parse(&data[34..44])?);
            self.calculate_offset();
        }
        Ok(())
    }

    /// Calculate offset from timestamps.
    fn calculate_offset(&mut self) {
        if let (Some(t1), Some(t2), Some(t3), Some(t4)) = (self.t1, self.t2, self.t3, self.t4) {
            // offset = ((t2 - t1) + (t3 - t4)) / 2
            // delay = ((t2 - t1) - (t3 - t4)) / 2

            let t1_ns = t1.to_nanos() as i128;
            let t2_ns = t2.to_nanos() as i128;
            let t3_ns = t3.to_nanos() as i128;
            let t4_ns = t4.to_nanos() as i128;

            let offset = ((t2_ns - t1_ns) + (t3_ns - t4_ns)) / 2;
            let delay = ((t2_ns - t1_ns) - (t3_ns - t4_ns)) / 2;

            self.offset = ClockOffset {
                offset_ns: offset as i64,
                error_ns: (delay.abs() / 2) as u64,
                rtt_ns: delay.abs() as u64,
            };

            self.state = PtpState::Synchronized;

            // Clear for next cycle
            self.t1 = None;
            self.t2 = None;
            self.t3 = None;
            self.t4 = None;
        }
    }

    /// Get current state.
    pub fn state(&self) -> PtpState {
        self.state
    }

    /// Get clock offset in nanoseconds.
    pub fn offset_ns(&self) -> i64 {
        self.offset.offset_ns
    }

    /// Get path delay in nanoseconds.
    pub fn delay_ns(&self) -> u64 {
        self.offset.rtt_ns
    }

    /// Convert local timestamp to master time.
    pub fn local_to_master(&self, local_ns: u64) -> u64 {
        (local_ns as i64 + self.offset.offset_ns) as u64
    }

    /// Convert master timestamp to local time.
    pub fn master_to_local(&self, master_ns: u64) -> u64 {
        (master_ns as i64 - self.offset.offset_ns) as u64
    }
}

#[async_trait]
impl TimingProtocol for PtpClient {
    async fn start(&mut self) -> Result<()> {
        self.bind()?;
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        self.event_socket = None;
        self.general_socket = None;
        self.state = PtpState::Unsynchronized;
        Ok(())
    }

    async fn sync(&mut self) -> Result<ClockOffset> {
        // In real PTP, we'd wait for Sync/Follow_Up from master
        // For active sync, send Delay_Req and wait for response
        self.send_delay_req()?;

        // Read response
        let socket = self.event_socket.as_ref()
            .ok_or_else(|| Error::Rtsp(
                airplay_core::error::RtspError::NoSession
            ))?;

        let mut buf = [0u8; 128];
        let (len, _) = socket.recv_from(&mut buf)?;

        let header = PtpHeader::parse(&buf[..len])?;
        if header.message_type == PtpMessageType::DelayResp {
            self.process_delay_resp(&header, &buf[..len])?;
        }

        Ok(self.offset)
    }

    fn offset(&self) -> ClockOffset {
        self.offset
    }

    fn is_synchronized(&self) -> bool {
        self.state == PtpState::Synchronized
    }

    fn local_to_remote(&self, local_ns: u64) -> u64 {
        self.local_to_master(local_ns)
    }

    fn remote_to_local(&self, remote_ns: u64) -> u64 {
        self.master_to_local(remote_ns)
    }
}

/// PTP master/grandmaster for AirPlay 2.
///
/// The sender acts as PTP master, and receivers sync to us.
/// For gPTP bidirectional mode, we also sync TO the receiver's clock.
pub struct PtpMaster {
    event_socket: Option<std::sync::Arc<tokio::net::UdpSocket>>,
    general_socket: Option<std::sync::Arc<tokio::net::UdpSocket>>,
    sequence_id: u16,
    clock_identity: [u8; 8],
    port: u16,
    running: bool,
    sync_task: Option<tokio::task::JoinHandle<()>>,
    offset_tx: Option<tokio::sync::watch::Sender<ClockOffset>>,
}

impl PtpMaster {
    /// Create new PTP master.
    pub fn new() -> Self {
        // Generate a clock identity from system time (in real PTP this would be based on MAC address)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let clock_identity = (now as u64).to_be_bytes();

        Self {
            event_socket: None,
            general_socket: None,
            sequence_id: 0,
            clock_identity,
            port: PTP_EVENT_PORT,
            running: false,
            sync_task: None,
            offset_tx: None,
        }
    }

    /// Set the offset sender for bidirectional gPTP
    pub fn set_offset_sender(&mut self, tx: tokio::sync::watch::Sender<ClockOffset>) {
        self.offset_tx = Some(tx);
    }

    /// Start the PTP master, binding to ports.
    pub async fn start(&mut self) -> Result<()> {
        use tokio::net::UdpSocket;

        // Bind to PTP event port 319 (requires root)
        let event = UdpSocket::bind(("0.0.0.0", PTP_EVENT_PORT)).await
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("Failed to bind PTP event port {}: {} (requires root)", PTP_EVENT_PORT, e)
            ))?;

        // Bind to PTP general port 320 (requires root)
        let general = UdpSocket::bind(("0.0.0.0", PTP_GENERAL_PORT)).await
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("Failed to bind PTP general port {}: {} (requires root)", PTP_GENERAL_PORT, e)
            ))?;

        let event = std::sync::Arc::new(event);
        let general = std::sync::Arc::new(general);

        self.event_socket = Some(event.clone());
        self.general_socket = Some(general.clone());
        self.running = true;

        tracing::info!("PTP master started on ports {}/{}", PTP_EVENT_PORT, PTP_GENERAL_PORT);

        // Start background task to handle incoming messages and calculate offset
        let event_clone = event.clone();
        let general_clone = general.clone();
        let clock_identity = self.clock_identity;
        let offset_tx = self.offset_tx.clone();

        // Spawn task to listen on both ports
        self.sync_task = Some(tokio::spawn(async move {
            let mut event_buf = [0u8; 1024];
            let mut general_buf = [0u8; 1024];

            // Bidirectional gPTP: track timestamps for syncing TO HomePod's clock
            let mut t1: Option<PtpTimestamp> = None;  // HomePod's send time (from Follow_Up)
            let mut t2: Option<PtpTimestamp> = None;  // Our receive time (when we got Sync)
            let mut t3: Option<PtpTimestamp> = None;  // Our send time (when we send Delay_Req)
            let mut delay_req_seq: u16 = 0;
            let mut master_addr: Option<std::net::SocketAddr> = None;

            tracing::info!("PTP master: listening for messages on ports 319 and 320 (bidirectional gPTP)");
            loop {
                tokio::select! {
                    // Listen on event port (319) for Delay_Req
                    result = event_clone.recv_from(&mut event_buf) => {
                        match result {
                            Ok((len, src)) => {
                                if let Ok(header) = PtpHeader::parse(&event_buf[..len]) {
                                    tracing::info!("gPTP: Received message on port 319: type={:?}, seq={}, from={}, len={}",
                                        header.message_type, header.sequence_id, src, len);

                                    match header.message_type {
                                        PtpMessageType::Sync => {
                                            // HomePod sent us a Sync - capture receive time (t2)
                                            t2 = Some(PtpTimestamp::now());
                                            master_addr = Some(src);
                                            tracing::trace!("gPTP: Received Sync from HomePod (seq={}), t2 captured", header.sequence_id);
                                        }
                                        PtpMessageType::DelayResp => {
                                            tracing::info!("gPTP: Received Delay_Resp from HomePod (len={})", len);
                                            // HomePod's response to our Delay_Req - extract t4 and calculate offset
                                            if len >= 44 {
                                                if let Ok(t4) = PtpTimestamp::parse(&event_buf[34..44]) {
                                                    tracing::info!("gPTP: Parsed t4 timestamp: {}.{:09}s", t4.seconds, t4.nanoseconds);
                                                    tracing::info!("gPTP: Current timestamps - t1={:?}, t2={:?}, t3={:?}", t1, t2, t3);
                                                    if let (Some(t1v), Some(t2v), Some(t3v)) = (t1, t2, t3) {
                                                        let t1_ns = t1v.to_nanos() as i128;
                                                        let t2_ns = t2v.to_nanos() as i128;
                                                        let t3_ns = t3v.to_nanos() as i128;
                                                        let t4_ns = t4.to_nanos() as i128;

                                                        let offset_val = ((t2_ns - t1_ns) + (t3_ns - t4_ns)) / 2;
                                                        let delay = ((t2_ns - t1_ns) - (t3_ns - t4_ns)) / 2;

                                                        let clock_offset = ClockOffset {
                                                            offset_ns: offset_val as i64,
                                                            error_ns: (delay.abs() / 2) as u64,
                                                            rtt_ns: delay.abs() as u64,
                                                        };

                                                        tracing::info!("gPTP: Synchronized to HomePod: offset={}ns, delay={}ns",
                                                            clock_offset.offset_ns, clock_offset.rtt_ns);

                                                        if let Some(ref tx) = offset_tx {
                                                            let _ = tx.send(clock_offset);
                                                        }

                                                        // Clear for next cycle
                                                        t1 = None;
                                                        t2 = None;
                                                        t3 = None;
                                                    }
                                                }
                                            }
                                        }
                                        PtpMessageType::DelayReq => {
                                            // Receiver sent us Delay_Req - send Delay_Resp
                                            tracing::info!("PTP: Received Delay_Req from {} (seq={})", src, header.sequence_id);
                                            let recv_time = PtpTimestamp::now();
                                            if let Err(e) = Self::send_delay_resp_static(
                                                &event_clone,
                                                src,
                                                header.sequence_id,
                                                &clock_identity,
                                                recv_time,
                                                &header.source_port_identity,
                                            ).await {
                                                tracing::warn!("Failed to send Delay_Resp: {}", e);
                                            } else {
                                                tracing::trace!("PTP: Sent Delay_Resp to {} (seq={}, t4={}.{:09}s)",
                                                    src, header.sequence_id, recv_time.seconds, recv_time.nanoseconds);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("PTP event socket error: {}", e);
                                break;
                            }
                        }
                    }
                    // Listen on general port (320) for Signaling, Announce, etc.
                    result = general_clone.recv_from(&mut general_buf) => {
                        match result {
                            Ok((len, src)) => {
                                if let Ok(header) = PtpHeader::parse(&general_buf[..len]) {
                                    tracing::info!("gPTP: Received message on port 320: type={:?}, seq={}, from={}, len={}",
                                        header.message_type, header.sequence_id, src, len);

                                    // Determine TLV start offset based on message type
                                    // Signaling: 34-byte header + 10-byte targetPortIdentity = 44
                                    // Follow_Up: 34-byte header + 10-byte preciseOriginTimestamp = 44
                                    // Announce: 34-byte header + 10-byte originTimestamp + 16+ announce fields = varies
                                    let tlv_offset = match header.message_type {
                                        PtpMessageType::Signaling => 44,  // After targetPortIdentity
                                        PtpMessageType::FollowUp => 44,   // After preciseOriginTimestamp
                                        PtpMessageType::Announce => 64,   // After announce data fields
                                        _ => 34,
                                    };

                                    // Parse TLVs if message is long enough
                                    if len > tlv_offset {
                                        let tlvs = parse_tlvs(&general_buf[tlv_offset..len]);

                                        for (tlv_type, tlv_len, tlv_data) in tlvs {
                                            tracing::debug!("  TLV: type=0x{:04x}, len={}", tlv_type, tlv_len);

                                            // Organization Extension TLV (0x0003)
                                            if tlv_type == 0x0003 && tlv_data.len() >= 6 {
                                                let org_id = &tlv_data[0..3];
                                                let org_subtype = &tlv_data[3..6];
                                                let payload = &tlv_data[6..];

                                                let org_hex: String = org_id.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                                                let sub_hex: String = org_subtype.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");

                                                tracing::info!("    Org TLV: org_id=0x{}, subtype=0x{}, payload_len={}",
                                                    org_hex, sub_hex, payload.len());

                                                // Log Apple TLV payload
                                                if org_id == [0x00, 0x0d, 0x93] {
                                                    let payload_hex: String = payload.iter()
                                                        .take(16)
                                                        .map(|b| format!("{:02x}", b))
                                                        .collect::<Vec<_>>()
                                                        .join(" ");
                                                    tracing::info!("    Apple TLV payload (first 16 bytes): {}", payload_hex);
                                                }
                                            }
                                        }
                                    }

                                    // Handle specific message types
                                    match header.message_type {
                                        PtpMessageType::FollowUp => {
                                            // Extract t1 from HomePod's Follow_Up and send Delay_Req
                                            if len >= 44 {
                                                if let Ok(timestamp) = PtpTimestamp::parse(&general_buf[34..44]) {
                                                    t1 = Some(timestamp);
                                                    tracing::trace!("gPTP: Received Follow_Up from HomePod (seq={}, t1={}.{:09}s)",
                                                        header.sequence_id, timestamp.seconds, timestamp.nanoseconds);

                                                    // Send Delay_Req to complete the timing exchange
                                                    if let Some(master) = master_addr {
                                                        delay_req_seq = delay_req_seq.wrapping_add(1);
                                                        let delay_header = PtpHeader::new(PtpMessageType::DelayReq, delay_req_seq);

                                                        // Capture t3 before sending
                                                        t3 = Some(PtpTimestamp::now());

                                                        let mut delay_packet = [0u8; 44];
                                                        delay_packet[..34].copy_from_slice(&delay_header.serialize());
                                                        delay_packet[34..44].copy_from_slice(&t3.unwrap().serialize());

                                                        let master_event = std::net::SocketAddr::new(master.ip(), PTP_EVENT_PORT);
                                                        if let Err(e) = event_clone.send_to(&delay_packet, master_event).await {
                                                            tracing::warn!("Failed to send Delay_Req: {}", e);
                                                        } else {
                                                            tracing::info!("gPTP: Sent Delay_Req to HomePod (seq={})", delay_req_seq);
                                                        }
                                                    } else {
                                                        tracing::warn!("gPTP: Cannot send Delay_Req - master_addr is None");
                                                    }
                                                }
                                            }
                                        }
                                        PtpMessageType::Signaling => {
                                            tracing::info!("gPTP: Received Signaling from HomePod - negotiation in progress");
                                            // TODO: Respond to Signaling with our own capabilities
                                        }
                                        PtpMessageType::Announce => {
                                            // Parse clock quality from Announce message (bytes 47-49 in message)
                                            if len >= 50 {
                                                let clock_class = general_buf[47];
                                                tracing::info!("gPTP: Received Announce - HomePod clock class={} (ours=193)", clock_class);
                                                // Clock class 248 = slave-only, 193 = better master
                                                // We should win BMCA with clock class 193
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("PTP general socket error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        }));

        Ok(())
    }

    /// Send Sync + Follow_Up to a specific address.
    pub async fn send_sync(&mut self, dest: SocketAddr) -> Result<()> {
        let event_socket = self.event_socket.as_ref()
            .ok_or_else(|| Error::Rtsp(airplay_core::error::RtspError::NoSession))?;
        let general_socket = self.general_socket.as_ref()
            .ok_or_else(|| Error::Rtsp(airplay_core::error::RtspError::NoSession))?;

        self.sequence_id = self.sequence_id.wrapping_add(1);
        let seq = self.sequence_id;

        // Build source port identity (clock identity + port number)
        let mut source_port_identity = [0u8; 10];
        source_port_identity[..8].copy_from_slice(&self.clock_identity);
        source_port_identity[8..10].copy_from_slice(&1u16.to_be_bytes()); // port 1

        // Send Sync message (event port) - two-step: timestamp in Follow_Up
        let mut sync_header = PtpHeader::new(PtpMessageType::Sync, seq);
        sync_header.flags = 0x0200; // Two-step flag
        sync_header.source_port_identity = source_port_identity;

        let mut sync_packet = [0u8; 44];
        sync_packet[..34].copy_from_slice(&sync_header.serialize());
        // Sync timestamp field is zeroed (actual time sent in Follow_Up)

        event_socket.send_to(&sync_packet, dest).await?;
        let sync_time = PtpTimestamp::now(); // Capture immediately after send for accurate t1
        tracing::debug!("gPTP: Sent Sync to {}:{} (seq={})", dest.ip(), dest.port(), seq);

        // Send Follow_Up message (general port) with precise timestamp + gPTP TLV
        let mut followup_header = PtpHeader::new(PtpMessageType::FollowUp, seq);
        followup_header.source_port_identity = source_port_identity;

        // Create Follow_Up Information TLV for gPTP
        let followup_tlv = FollowUpInformationTlv::new();
        let tlv_bytes = followup_tlv.serialize();

        // Update message length to include TLV
        followup_header.message_length = 44 + tlv_bytes.len() as u16;

        let mut followup_packet = Vec::new();
        followup_packet.extend_from_slice(&followup_header.serialize());
        followup_packet.extend_from_slice(&sync_time.serialize());
        followup_packet.extend_from_slice(&tlv_bytes);

        let general_dest = SocketAddr::new(dest.ip(), PTP_GENERAL_PORT);
        general_socket.send_to(&followup_packet, general_dest).await?;
        tracing::debug!("gPTP: Sent Follow_Up to {}:{} (seq={}, t1={}.{:09}s, with TLV)",
            general_dest.ip(), general_dest.port(), seq, sync_time.seconds, sync_time.nanoseconds);

        Ok(())
    }

    /// Static helper to send Delay_Resp (used from background task).
    async fn send_delay_resp_static(
        socket: &tokio::net::UdpSocket,
        dest: SocketAddr,
        sequence_id: u16,
        clock_identity: &[u8; 8],
        recv_time: PtpTimestamp,
        requesting_port_identity: &[u8; 10],
    ) -> Result<()> {
        let mut source_port_identity = [0u8; 10];
        source_port_identity[..8].copy_from_slice(clock_identity);
        source_port_identity[8..10].copy_from_slice(&1u16.to_be_bytes());

        let mut header = PtpHeader::new(PtpMessageType::DelayResp, sequence_id);
        header.source_port_identity = source_port_identity;
        header.message_length = 54; // 34 header + 10 timestamp + 10 requesting port identity

        let mut packet = [0u8; 54];
        packet[..34].copy_from_slice(&header.serialize());
        packet[34..44].copy_from_slice(&recv_time.serialize());
        packet[44..54].copy_from_slice(requesting_port_identity);

        socket.send_to(&packet, dest).await?;
        Ok(())
    }

    /// Stop the PTP master.
    pub async fn stop(&mut self) {
        self.running = false;
        if let Some(task) = self.sync_task.take() {
            task.abort();
        }
        self.event_socket = None;
        self.general_socket = None;
        tracing::info!("PTP master stopped");
    }

    /// Get the port we're listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get reference to event socket for external sync sending.
    pub fn event_socket(&self) -> Option<&std::sync::Arc<tokio::net::UdpSocket>> {
        self.event_socket.as_ref()
    }

    /// Get reference to general socket for external sync sending.
    pub fn general_socket(&self) -> Option<&std::sync::Arc<tokio::net::UdpSocket>> {
        self.general_socket.as_ref()
    }

    /// Get the clock identity.
    pub fn clock_identity(&self) -> [u8; 8] {
        self.clock_identity
    }
}

impl Default for PtpMaster {
    fn default() -> Self {
        Self::new()
    }
}

/// Send a PTP Announce message to a destination.
///
/// IEEE 1588 Announce (64 bytes): 34-byte header + 10-byte origin timestamp + 20-byte body.
/// The receiver uses this to run the Best Master Clock Algorithm (BMCA)
/// and accept us as the grandmaster before processing Sync messages.
pub async fn send_ptp_announce(
    general_socket: &tokio::net::UdpSocket,
    dest: std::net::SocketAddr,
    clock_identity: &[u8; 8],
    announce_seq: &mut u16,
    clock_class: u8,  // 193 = master, 248+ = slave
) -> Result<()> {
    *announce_seq = announce_seq.wrapping_add(1);
    let seq = *announce_seq;

    let mut source_port_identity = [0u8; 10];
    source_port_identity[..8].copy_from_slice(clock_identity);
    source_port_identity[8..10].copy_from_slice(&1u16.to_be_bytes());

    let mut header = PtpHeader::new(PtpMessageType::Announce, seq);
    header.source_port_identity = source_port_identity;
    header.message_length = 64; // 34 header + 10 timestamp + 20 announce body
    header.log_message_interval = 1; // Announce interval: 2^1 = 2 seconds

    let mut packet = [0u8; 64];
    packet[..34].copy_from_slice(&header.serialize());

    // Bytes 34-43: Origin timestamp (10 bytes) — zeroed for Announce
    // (already zero)

    // Bytes 44-63: Announce body (20 bytes)
    // Bytes 44-45: currentUtcOffset (i16 BE) — 37 seconds (TAI - UTC as of 2017+)
    packet[44..46].copy_from_slice(&37i16.to_be_bytes());
    // Byte 46: reserved
    // Byte 47: grandmasterPriority1 — 128 (default)
    packet[47] = 128;
    // Bytes 48-51: grandmasterClockQuality (4 bytes)
    //   Byte 48: clockClass — 193 (master), 248+ (slave)
    //   Lower number = better clock, wins BMCA election
    packet[48] = clock_class;
    //   Byte 49: clockAccuracy — 0xFE (unknown)
    packet[49] = 0xFE;
    //   Bytes 50-51: offsetScaledLogVariance — 0xFFFF (unknown)
    packet[50..52].copy_from_slice(&0xFFFFu16.to_be_bytes());
    // Byte 52: grandmasterPriority2 — 128 (default)
    packet[52] = 128;
    // Bytes 53-60: grandmasterIdentity (8 bytes) — same as our clock identity
    packet[53..61].copy_from_slice(clock_identity);
    // Bytes 61-62: stepsRemoved (u16 BE) — 0 (we are the grandmaster)
    // (already zero)
    // Byte 63: timeSource — 0xA0 (internal oscillator)
    packet[63] = 0xA0;

    let general_dest = std::net::SocketAddr::new(dest.ip(), PTP_GENERAL_PORT);
    general_socket.send_to(&packet, general_dest).await?;
    tracing::info!("PTP: Sent Announce to {}:{} (seq={}, clockClass={})",
        general_dest.ip(), general_dest.port(), seq, clock_class);

    Ok(())
}

/// Parse TLVs from a PTP message body (starting after the 34-byte header)
fn parse_tlvs(data: &[u8]) -> Vec<(u16, u16, Vec<u8>)> {
    let mut tlvs = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let tlv_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;

        if offset + length as usize > data.len() {
            tracing::warn!("TLV length exceeds buffer: type={}, length={}", tlv_type, length);
            break;
        }

        let tlv_data = data[offset..offset + length as usize].to_vec();
        tlvs.push((tlv_type, length, tlv_data));
        offset += length as usize;
    }

    tlvs
}

/// Send a gPTP Signaling message with Message Interval Request TLV.
///
/// This is sent during initial handshake to negotiate timing intervals with the receiver.
pub async fn send_ptp_signaling(
    general_socket: &tokio::net::UdpSocket,
    dest: std::net::SocketAddr,
    clock_identity: &[u8; 8],
    sequence_id: &mut u16,
    sync_interval_log: i8,      // -3 for 125ms (2^-3 = 1/8 second)
    announce_interval_log: i8,  // -2 for 250ms (2^-2 = 1/4 second)
) -> Result<()> {
    *sequence_id = sequence_id.wrapping_add(1);
    let seq = *sequence_id;

    let mut source_port_identity = [0u8; 10];
    source_port_identity[..8].copy_from_slice(clock_identity);
    source_port_identity[8..10].copy_from_slice(&1u16.to_be_bytes());

    let mut header = PtpHeader::new(PtpMessageType::Signaling, seq);
    header.source_port_identity = source_port_identity;

    // Create Message Interval Request TLV
    let tlv = MessageIntervalRequestTlv::new(sync_interval_log, announce_interval_log);
    let tlv_bytes = tlv.serialize();

    // Create Apple TLV subtype 0x01 (based on HomePod's format)
    // HomePod sends: 00 04 03 01 00 00 00 00 00 00 00 00 00 20 13 9f
    // Pattern suggests: [flags?] [intervals?] [reserved] [some ID?]
    let apple_tlv_01_payload = vec![
        0x00, 0x04, sync_interval_log as u8, announce_interval_log as u8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  // Simplified - zeros instead of HomePod's ID
    ];
    let apple_tlv_01 = AppleTlv::new([0x00, 0x00, 0x01], apple_tlv_01_payload);
    let apple_tlv_01_bytes = apple_tlv_01.serialize();

    // Create Apple TLV subtype 0x05 (based on HomePod's format)
    // HomePod sends: 00 10 03 01 ... (26 bytes total)
    let apple_tlv_05_payload = vec![
        0x00, 0x10, sync_interval_log as u8, announce_interval_log as u8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let apple_tlv_05 = AppleTlv::new([0x00, 0x00, 0x05], apple_tlv_05_payload);
    let apple_tlv_05_bytes = apple_tlv_05.serialize();

    // Total message length: 34 (header) + 10 (target port identity) + all TLVs
    header.message_length = 34 + 10 + tlv_bytes.len() as u16
        + apple_tlv_01_bytes.len() as u16
        + apple_tlv_05_bytes.len() as u16;

    let mut packet = Vec::new();
    packet.extend_from_slice(&header.serialize());

    // Target port identity (all 0xFF for wildcard = all ports)
    packet.extend_from_slice(&[0xFF; 10]);

    // Append TLVs (802.1AS first, then Apple TLVs)
    packet.extend_from_slice(&tlv_bytes);
    packet.extend_from_slice(&apple_tlv_01_bytes);
    packet.extend_from_slice(&apple_tlv_05_bytes);

    let general_dest = std::net::SocketAddr::new(dest.ip(), PTP_GENERAL_PORT);
    general_socket.send_to(&packet, general_dest).await?;
    tracing::info!("gPTP: Sent Signaling to {}:{} (seq={}, sync={}ms, announce={}ms)",
        general_dest.ip(), general_dest.port(), seq,
        1000 / (1 << (-sync_interval_log)),
        1000 / (1 << (-announce_interval_log)));

    Ok(())
}

/// Send a single PTP Sync + Follow_Up message pair to a destination.
///
/// This is a standalone helper for use in external sync tasks.
pub async fn send_ptp_sync(
    event_socket: &tokio::net::UdpSocket,
    general_socket: &tokio::net::UdpSocket,
    dest: std::net::SocketAddr,
    clock_identity: &[u8; 8],
    sequence_id: &mut u16,
) -> Result<()> {
    *sequence_id = sequence_id.wrapping_add(1);
    let seq = *sequence_id;

    // Build source port identity (clock identity + port number)
    let mut source_port_identity = [0u8; 10];
    source_port_identity[..8].copy_from_slice(clock_identity);
    source_port_identity[8..10].copy_from_slice(&1u16.to_be_bytes()); // port 1

    // Send Sync message (event port) - two-step: timestamp in Follow_Up
    let mut sync_header = PtpHeader::new(PtpMessageType::Sync, seq);
    sync_header.flags = 0x0200; // Two-step flag
    sync_header.source_port_identity = source_port_identity;

    let mut sync_packet = [0u8; 44];
    sync_packet[..34].copy_from_slice(&sync_header.serialize());
    // Sync timestamp field is zeroed (actual time sent in Follow_Up)

    event_socket.send_to(&sync_packet, dest).await?;
    let sync_time = PtpTimestamp::now(); // Capture immediately after send for accurate t1
    tracing::debug!("gPTP: Sent Sync to {}:{} (seq={})", dest.ip(), dest.port(), seq);

    // Send Follow_Up message (general port) with precise timestamp + gPTP TLV
    let mut followup_header = PtpHeader::new(PtpMessageType::FollowUp, seq);
    followup_header.source_port_identity = source_port_identity;

    // Create Follow_Up Information TLV for gPTP
    let followup_tlv = FollowUpInformationTlv::new();
    let tlv_bytes = followup_tlv.serialize();

    // Update message length to include TLV
    followup_header.message_length = 44 + tlv_bytes.len() as u16;

    let mut followup_packet = Vec::new();
    followup_packet.extend_from_slice(&followup_header.serialize());
    followup_packet.extend_from_slice(&sync_time.serialize());
    followup_packet.extend_from_slice(&tlv_bytes);

    let general_dest = std::net::SocketAddr::new(dest.ip(), PTP_GENERAL_PORT);
    general_socket.send_to(&followup_packet, general_dest).await?;
    tracing::debug!("gPTP: Sent Follow_Up to {}:{} (seq={}, t1={}.{:09}s, with TLV)",
        general_dest.ip(), general_dest.port(), seq, sync_time.seconds, sync_time.nanoseconds);

    Ok(())
}

/// Background PTP sync task.
pub async fn ptp_sync_loop(
    client: &mut PtpClient,
    interval: Duration,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                if let Err(e) = client.sync().await {
                    tracing::warn!("PTP sync failed: {}", e);
                }
            }
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Run an async PTP slave loop that listens for Sync/Follow_Up from the master
/// (HomePod/AirPlay receiver) and calculates clock offset.
///
/// The receiver is always the PTP master in AirPlay 2. Our sender acts as slave:
/// 1. Listen for Sync on event port (records t2 = local receive time)
/// 2. Listen for Follow_Up on general port (contains t1 = master send time)
/// 3. Send Delay_Req after Follow_Up
/// 4. Process Delay_Resp (contains t4 = master receive time)
/// 5. Calculate offset = ((t2-t1) + (t3-t4)) / 2
pub async fn run_ptp_slave(
    master_ip: std::net::IpAddr,
    offset_tx: tokio::sync::watch::Sender<ClockOffset>,
) -> Result<()> {
    use tokio::net::UdpSocket;

    // Bind to PTP ports (privileged, fall back to ephemeral)
    let event_socket = match UdpSocket::bind(("0.0.0.0", PTP_EVENT_PORT)).await {
        Ok(s) => {
            tracing::info!("PTP slave bound to event port {}", PTP_EVENT_PORT);
            s
        }
        Err(_) => {
            let s = UdpSocket::bind("0.0.0.0:0").await?;
            tracing::warn!(
                "PTP slave using ephemeral event port {}",
                s.local_addr()?.port()
            );
            s
        }
    };

    let general_socket = match UdpSocket::bind(("0.0.0.0", PTP_GENERAL_PORT)).await {
        Ok(s) => {
            tracing::info!("PTP slave bound to general port {}", PTP_GENERAL_PORT);
            s
        }
        Err(_) => {
            let s = UdpSocket::bind("0.0.0.0:0").await?;
            tracing::warn!(
                "PTP slave using ephemeral general port {}",
                s.local_addr()?.port()
            );
            s
        }
    };

    let master_event = std::net::SocketAddr::new(master_ip, PTP_EVENT_PORT);
    let master_general = std::net::SocketAddr::new(master_ip, PTP_GENERAL_PORT);

    // Generate clock identity for slave
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let clock_identity = (now as u64).to_be_bytes();

    let mut t1: Option<PtpTimestamp> = None;
    let mut t2: Option<PtpTimestamp> = None;
    let mut t3: Option<PtpTimestamp> = None;
    let mut sequence_id: u16 = 0;
    let mut announce_seq: u16 = 0;
    let mut signaling_seq: u16 = 0;

    let mut event_buf = [0u8; 256];
    let mut general_buf = [0u8; 256];

    tracing::info!(
        "PTP slave started, listening for Sync from master {}",
        master_ip
    );

    // gPTP negotiation: Send initial Announce + Signaling to HomePod
    // This triggers HomePod to start sending its Sync/Follow_Up messages
    tracing::info!("gPTP slave: Sending initial Announce+Signaling handshake");

    if let Err(e) = send_ptp_announce(
        &general_socket,
        master_general,
        &clock_identity,
        &mut announce_seq,
        255,  // Worst clock class - we want HomePod to be master
    ).await {
        tracing::warn!("Failed to send initial Announce: {}", e);
    }

    if let Err(e) = send_ptp_signaling(
        &general_socket,
        master_general,
        &clock_identity,
        &mut signaling_seq,
        -3,  // Request 125ms sync interval
        -2,  // Request 250ms announce interval
    ).await {
        tracing::warn!("Failed to send initial Signaling: {}", e);
    }

    tracing::info!("gPTP slave: Handshake complete, waiting for master's Sync messages");

    // Periodic Announce interval (gPTP: 250ms = 2^-2)
    let mut announce_interval = tokio::time::interval(std::time::Duration::from_millis(250));
    announce_interval.tick().await; // Skip first immediate tick

    loop {
        tokio::select! {
            _ = announce_interval.tick() => {
                // Send periodic Announce to maintain gPTP session
                if let Err(e) = send_ptp_announce(
                    &general_socket,
                    master_general,
                    &clock_identity,
                    &mut announce_seq,
                    255,  // Worst clock class - we want HomePod to be master
                ).await {
                    tracing::warn!("Failed to send periodic Announce: {}", e);
                } else {
                    tracing::trace!("gPTP slave: Sent periodic Announce (seq={})", announce_seq);
                }
            }
            result = event_socket.recv_from(&mut event_buf) => {
                match result {
                    Ok((len, _src)) => {
                        if let Ok(header) = PtpHeader::parse(&event_buf[..len]) {
                            match header.message_type {
                                PtpMessageType::Sync => {
                                    t2 = Some(PtpTimestamp::now());
                                    tracing::trace!(
                                        "PTP: Received Sync (seq={})",
                                        header.sequence_id
                                    );
                                }
                                PtpMessageType::DelayResp => {
                                    if len >= 44 {
                                        if let Ok(t4) = PtpTimestamp::parse(&event_buf[34..44]) {
                                            if let (Some(t1v), Some(t2v), Some(t3v)) =
                                                (t1, t2, t3)
                                            {
                                                let t1_ns = t1v.to_nanos() as i128;
                                                let t2_ns = t2v.to_nanos() as i128;
                                                let t3_ns = t3v.to_nanos() as i128;
                                                let t4_ns = t4.to_nanos() as i128;

                                                let offset_val =
                                                    ((t2_ns - t1_ns) + (t3_ns - t4_ns)) / 2;
                                                let delay =
                                                    ((t2_ns - t1_ns) - (t3_ns - t4_ns)) / 2;

                                                let clock_offset = ClockOffset {
                                                    offset_ns: offset_val as i64,
                                                    error_ns: (delay.abs() / 2) as u64,
                                                    rtt_ns: delay.abs() as u64,
                                                };

                                                tracing::debug!(
                                                    "PTP synchronized: offset={}ns, delay={}ns",
                                                    clock_offset.offset_ns,
                                                    clock_offset.rtt_ns
                                                );
                                                let _ = offset_tx.send(clock_offset);
                                            }
                                            // Clear for next cycle
                                            t1 = None;
                                            t2 = None;
                                            t3 = None;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("PTP event socket error: {}", e);
                    }
                }
            }
            result = general_socket.recv_from(&mut general_buf) => {
                match result {
                    Ok((len, _src)) => {
                        if let Ok(header) = PtpHeader::parse(&general_buf[..len]) {
                            if header.message_type == PtpMessageType::FollowUp && len >= 44 {
                                if let Ok(ts) = PtpTimestamp::parse(&general_buf[34..44]) {
                                    t1 = Some(ts);
                                    tracing::trace!(
                                        "PTP: Received Follow_Up (seq={}, t1={:?})",
                                        header.sequence_id,
                                        ts
                                    );

                                    // Send Delay_Req after receiving Follow_Up
                                    sequence_id = sequence_id.wrapping_add(1);
                                    let delay_header = PtpHeader::new(
                                        PtpMessageType::DelayReq,
                                        sequence_id,
                                    );

                                    // Capture timestamp just before send (t3)
                                    // Note: Unlike Sync, Delay_Req includes timestamp in the packet
                                    t3 = Some(PtpTimestamp::now());

                                    let mut delay_packet = [0u8; 44];
                                    delay_packet[..34]
                                        .copy_from_slice(&delay_header.serialize());
                                    delay_packet[34..44]
                                        .copy_from_slice(&t3.unwrap().serialize());

                                    if let Err(e) = event_socket
                                        .send_to(&delay_packet, master_event)
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to send Delay_Req: {}",
                                            e
                                        );
                                    } else {
                                        tracing::trace!(
                                            "PTP: Sent Delay_Req (seq={})",
                                            sequence_id
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("PTP general socket error: {}", e);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod ptp_timestamp {
        use super::*;

        #[test]
        fn from_nanos_splits_correctly() {
            let ts = PtpTimestamp::from_nanos(1_234_567_890_123_456_789);
            assert_eq!(ts.seconds, 1_234_567_890);
            assert_eq!(ts.nanoseconds, 123_456_789);
        }

        #[test]
        fn to_nanos_combines_correctly() {
            let ts = PtpTimestamp {
                seconds: 1_234_567_890,
                nanoseconds: 123_456_789,
            };
            assert_eq!(ts.to_nanos(), 1_234_567_890_123_456_789);
        }

        #[test]
        fn serialize_is_10_bytes() {
            let ts = PtpTimestamp::now();
            let bytes = ts.serialize();
            assert_eq!(bytes.len(), 10);
        }

        #[test]
        fn parse_serialize_roundtrip() {
            let original = PtpTimestamp {
                seconds: 0x123456789ABC, // 48-bit value
                nanoseconds: 987_654_321,
            };
            let bytes = original.serialize();
            let parsed = PtpTimestamp::parse(&bytes).unwrap();

            // Only lower 48 bits of seconds are preserved
            assert_eq!(parsed.seconds, original.seconds & 0xFFFFFFFFFFFF);
            assert_eq!(parsed.nanoseconds, original.nanoseconds);
        }
    }

    mod ptp_header {
        use super::*;

        #[test]
        fn new_sets_fields() {
            let header = PtpHeader::new(PtpMessageType::Sync, 42);
            assert_eq!(header.message_type, PtpMessageType::Sync);
            assert_eq!(header.sequence_id, 42);
            assert_eq!(header.version, 2);
        }

        #[test]
        fn parse_sync_message() {
            let header = PtpHeader::new(PtpMessageType::Sync, 123);
            let bytes = header.serialize();
            let parsed = PtpHeader::parse(&bytes).unwrap();

            assert_eq!(parsed.message_type, PtpMessageType::Sync);
            assert_eq!(parsed.sequence_id, 123);
        }

        #[test]
        fn parse_follow_up_message() {
            let header = PtpHeader::new(PtpMessageType::FollowUp, 456);
            let bytes = header.serialize();
            let parsed = PtpHeader::parse(&bytes).unwrap();

            assert_eq!(parsed.message_type, PtpMessageType::FollowUp);
            assert_eq!(parsed.sequence_id, 456);
        }

        #[test]
        fn parse_delay_resp_message() {
            let header = PtpHeader::new(PtpMessageType::DelayResp, 789);
            let bytes = header.serialize();
            let parsed = PtpHeader::parse(&bytes).unwrap();

            assert_eq!(parsed.message_type, PtpMessageType::DelayResp);
            assert_eq!(parsed.sequence_id, 789);
        }

        #[test]
        fn serialize_delay_req_message() {
            let header = PtpHeader::new(PtpMessageType::DelayReq, 100);
            let bytes = header.serialize();

            assert_eq!(bytes[0], PtpMessageType::DelayReq as u8);
            assert_eq!(bytes.len(), 34);
        }
    }

    mod ptp_client {
        use super::*;

        #[test]
        fn new_starts_unsynchronized() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let client = PtpClient::new(addr, 44100);
            assert_eq!(client.state(), PtpState::Unsynchronized);
        }

        #[tokio::test]
        async fn start_opens_sockets() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // This may fail on systems without permission for ports 319/320
            // but should fall back to ephemeral ports
            let result = client.start().await;
            assert!(result.is_ok());
            assert!(client.event_socket.is_some());
            assert!(client.general_socket.is_some());
        }

        #[test]
        fn process_sync_stores_t2() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            let header = PtpHeader::new(PtpMessageType::Sync, 1);
            client.process_sync(&header);

            assert!(client.t2.is_some());
            assert_eq!(client.state(), PtpState::Synchronizing);
        }

        #[test]
        fn process_follow_up_stores_t1() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // Create a follow-up packet with timestamp
            let header = PtpHeader::new(PtpMessageType::FollowUp, 1);
            let ts = PtpTimestamp::from_nanos(1_000_000_000);

            let mut data = [0u8; 44];
            data[..34].copy_from_slice(&header.serialize());
            data[34..44].copy_from_slice(&ts.serialize());

            client.process_follow_up(&header, &data).unwrap();
            assert!(client.t1.is_some());
        }

        #[test]
        fn process_delay_resp_stores_t4() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            let header = PtpHeader::new(PtpMessageType::DelayResp, 1);
            let ts = PtpTimestamp::from_nanos(2_000_000_000);

            let mut data = [0u8; 44];
            data[..34].copy_from_slice(&header.serialize());
            data[34..44].copy_from_slice(&ts.serialize());

            client.process_delay_resp(&header, &data).unwrap();
            assert!(client.t4.is_some());
        }

        #[test]
        fn calculate_offset_with_all_timestamps() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // Set up timestamps
            client.t1 = Some(PtpTimestamp::from_nanos(100_000_000)); // Master send: 100ms
            client.t2 = Some(PtpTimestamp::from_nanos(110_000_000)); // Local recv: 110ms
            client.t3 = Some(PtpTimestamp::from_nanos(120_000_000)); // Local send: 120ms
            client.t4 = Some(PtpTimestamp::from_nanos(130_000_000)); // Master recv: 130ms

            client.calculate_offset();

            // offset = ((110-100) + (120-130)) / 2 = (10 + (-10)) / 2 = 0
            assert_eq!(client.offset.offset_ns, 0);
            assert_eq!(client.state(), PtpState::Synchronized);
        }
    }

    mod offset_calculation {
        use super::*;

        #[test]
        fn offset_zero_when_synchronized() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // Symmetric delay, no offset
            client.t1 = Some(PtpTimestamp::from_nanos(0));
            client.t2 = Some(PtpTimestamp::from_nanos(10_000_000));
            client.t3 = Some(PtpTimestamp::from_nanos(10_000_000));
            client.t4 = Some(PtpTimestamp::from_nanos(20_000_000));

            client.calculate_offset();

            // offset = ((10-0) + (10-20)) / 2 = (10 + (-10)) / 2 = 0
            assert_eq!(client.offset.offset_ns, 0);
        }

        #[test]
        fn offset_positive_when_master_ahead() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // Master is 5ms ahead
            client.t1 = Some(PtpTimestamp::from_nanos(15_000_000)); // Master at 15ms
            client.t2 = Some(PtpTimestamp::from_nanos(10_000_000)); // Local at 10ms
            client.t3 = Some(PtpTimestamp::from_nanos(20_000_000)); // Local at 20ms
            client.t4 = Some(PtpTimestamp::from_nanos(25_000_000)); // Master at 25ms

            client.calculate_offset();

            // offset = ((10-15) + (20-25)) / 2 = (-5 + (-5)) / 2 = -5ms
            // Negative means local is behind (master is ahead)
            assert!(client.offset.offset_ns < 0);
        }

        #[test]
        fn offset_negative_when_master_behind() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // Master is 5ms behind
            client.t1 = Some(PtpTimestamp::from_nanos(5_000_000));  // Master at 5ms
            client.t2 = Some(PtpTimestamp::from_nanos(10_000_000)); // Local at 10ms
            client.t3 = Some(PtpTimestamp::from_nanos(20_000_000)); // Local at 20ms
            client.t4 = Some(PtpTimestamp::from_nanos(15_000_000)); // Master at 15ms

            client.calculate_offset();

            // offset = ((10-5) + (20-15)) / 2 = (5 + 5) / 2 = 5ms
            // Positive means local is ahead (master is behind)
            assert!(client.offset.offset_ns > 0);
        }

        #[test]
        fn delay_calculation() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // 10ms one-way delay
            client.t1 = Some(PtpTimestamp::from_nanos(0));
            client.t2 = Some(PtpTimestamp::from_nanos(10_000_000));
            client.t3 = Some(PtpTimestamp::from_nanos(20_000_000));
            client.t4 = Some(PtpTimestamp::from_nanos(30_000_000));

            client.calculate_offset();

            // delay = ((10-0) - (20-30)) / 2 = (10 - (-10)) / 2 = 10ms
            assert_eq!(client.offset.rtt_ns, 10_000_000);
        }
    }

    mod state_transitions {
        use super::*;

        #[test]
        fn unsynchronized_to_synchronizing() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            assert_eq!(client.state(), PtpState::Unsynchronized);

            let header = PtpHeader::new(PtpMessageType::Sync, 1);
            client.process_sync(&header);

            assert_eq!(client.state(), PtpState::Synchronizing);
        }

        #[test]
        fn synchronizing_to_synchronized() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // Receive Sync
            let header = PtpHeader::new(PtpMessageType::Sync, 1);
            client.process_sync(&header);
            assert_eq!(client.state(), PtpState::Synchronizing);

            // Receive Follow_Up with t1
            client.t1 = Some(PtpTimestamp::from_nanos(0));

            // Send Delay_Req (simulated)
            client.t3 = Some(PtpTimestamp::from_nanos(10_000_000));

            // Receive Delay_Resp with t4
            client.t4 = Some(PtpTimestamp::from_nanos(20_000_000));

            client.calculate_offset();
            assert_eq!(client.state(), PtpState::Synchronized);
        }

        #[test]
        fn synchronized_maintained_on_updates() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);

            // First sync
            client.t1 = Some(PtpTimestamp::from_nanos(0));
            client.t2 = Some(PtpTimestamp::from_nanos(10_000_000));
            client.t3 = Some(PtpTimestamp::from_nanos(20_000_000));
            client.t4 = Some(PtpTimestamp::from_nanos(30_000_000));
            client.calculate_offset();

            assert_eq!(client.state(), PtpState::Synchronized);
            let first_offset = client.offset.offset_ns;

            // Second sync
            client.t1 = Some(PtpTimestamp::from_nanos(100_000_000));
            client.t2 = Some(PtpTimestamp::from_nanos(110_000_000));
            client.t3 = Some(PtpTimestamp::from_nanos(120_000_000));
            client.t4 = Some(PtpTimestamp::from_nanos(130_000_000));
            client.calculate_offset();

            assert_eq!(client.state(), PtpState::Synchronized);
            // Offset should be the same (symmetric delay, no drift)
            assert_eq!(client.offset.offset_ns, first_offset);
        }
    }

    mod timestamp_conversion {
        use super::*;

        #[test]
        fn local_to_master_applies_offset() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);
            client.offset.offset_ns = 5_000_000; // +5ms

            let master = client.local_to_master(10_000_000);
            assert_eq!(master, 15_000_000);
        }

        #[test]
        fn master_to_local_applies_offset() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);
            client.offset.offset_ns = 5_000_000; // +5ms

            let local = client.master_to_local(15_000_000);
            assert_eq!(local, 10_000_000);
        }

        #[test]
        fn roundtrip_conversion() {
            let addr: SocketAddr = "127.0.0.1:319".parse().unwrap();
            let mut client = PtpClient::new(addr, 44100);
            client.offset.offset_ns = 5_000_000;

            let original = 12345678u64;
            let master = client.local_to_master(original);
            let recovered = client.master_to_local(master);

            assert_eq!(recovered, original);
        }
    }
}
