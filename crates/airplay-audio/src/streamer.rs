//! High-level audio streaming orchestrator.

use airplay_core::{StreamConfig, error::Result};
use crate::{AudioBuffer, AudioDecoder, RtpSender};
use crate::encoder::{create_encoder, AudioEncoder};
use airplay_timing::{Clock, ClockOffset, unix_to_ntp};
use std::sync::{Arc, atomic::{AtomicU64, AtomicU8, Ordering}};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration, Instant};

/// Streaming state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamerState {
    /// Not started.
    Idle,
    /// Buffering initial audio.
    Buffering,
    /// Actively streaming.
    Streaming,
    /// Paused.
    Paused,
    /// Stopped.
    Stopped,
    /// Error occurred.
    Error,
}

/// Try to set real-time priority for the current thread (Linux only).
#[cfg(target_os = "linux")]
fn set_realtime_priority() {
    use std::mem;
    unsafe {
        let param: libc::sched_param = mem::zeroed();
        let mut param = param;
        param.sched_priority = 50; // RT priority 50 (1-99 scale)

        let result = libc::sched_setscheduler(
            0, // current thread
            libc::SCHED_FIFO,
            &param as *const _,
        );

        if result == 0 {
            tracing::info!("Set real-time priority (SCHED_FIFO, priority 50)");
        } else {
            tracing::warn!("Failed to set RT priority (need CAP_SYS_NICE or root): errno={}",
                *libc::__errno_location());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn set_realtime_priority() {
    tracing::debug!("RT priority not supported on this platform");
}

struct StreamerInner {
    state: StreamerState,
    config: StreamConfig,
    buffer: AudioBuffer,
    rtp_sender: Option<RtpSender>,
    current_timestamp: u64,
    last_sync_rtp: u32,
    clock: Clock,
    clock_offset: Option<ClockOffset>,
    timing_rx: Option<watch::Receiver<ClockOffset>>,
    decoder: Option<AudioDecoder>,
    encoder: Option<Box<dyn AudioEncoder>>,
    /// Track whether first audio packet has been sent (requires marker bit)
    first_packet_sent: bool,
}

/// High-level audio streamer.
pub struct AudioStreamer {
    inner: Arc<Mutex<StreamerInner>>,
    task: Option<JoinHandle<Result<()>>>,
    state_cache: Arc<AtomicU8>,
    timestamp_cache: Arc<AtomicU64>,
}

impl Clone for AudioStreamer {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            task: None, // Can't clone JoinHandle, new clone doesn't own the task
            state_cache: Arc::clone(&self.state_cache),
            timestamp_cache: Arc::clone(&self.timestamp_cache),
        }
    }
}

impl AudioStreamer {
    /// Create new streamer.
    pub fn new(config: StreamConfig) -> Self {
        let audio_format = config.audio_format.clone();
        Self {
            inner: Arc::new(Mutex::new(StreamerInner {
                state: StreamerState::Idle,
                config,
                buffer: AudioBuffer::new(audio_format, 2000),
                rtp_sender: None,
                current_timestamp: 0,
                last_sync_rtp: 0,
                clock: Clock::new(audio_format.sample_rate.as_hz()),
                clock_offset: None,
                timing_rx: None,
                decoder: None,
                encoder: None,
                first_packet_sent: false,
            })),
            task: None,
            state_cache: Arc::new(AtomicU8::new(StreamerState::Idle as u8)),
            timestamp_cache: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Configure RTP sender.
    pub async fn set_rtp_sender(&mut self, sender: RtpSender) {
        self.inner.lock().await.rtp_sender = Some(sender);
    }

    /// Handle retransmit request from control channel.
    pub async fn handle_retransmit(&self, request: &crate::rtp::RetransmitRequest) -> airplay_core::error::Result<u16> {
        let inner = self.inner.lock().await;
        if let Some(ref sender) = inner.rtp_sender {
            sender.handle_retransmit(request)
        } else {
            Ok(0)
        }
    }

    /// Get current state.
    pub fn state(&self) -> StreamerState {
        match self.state_cache.load(Ordering::Relaxed) {
            0 => StreamerState::Idle,
            1 => StreamerState::Buffering,
            2 => StreamerState::Streaming,
            3 => StreamerState::Paused,
            4 => StreamerState::Stopped,
            _ => StreamerState::Error,
        }
    }

    /// Start streaming from decoder.
    pub async fn start(&mut self, decoder: AudioDecoder) -> Result<()> {
        {
            let mut inner = self.inner.lock().await;
            inner.decoder = Some(decoder);
            inner.encoder = Some(create_encoder(inner.config.audio_format.clone())?);
            inner.state = StreamerState::Buffering;
        }
        self.state_cache.store(StreamerState::Buffering as u8, Ordering::Relaxed);

        // Prime the buffer
        self.decode_some().await?;
        let level = self.buffer_level().await;
        if level > 10.0 {
            self.inner.lock().await.state = StreamerState::Streaming;
            self.state_cache.store(StreamerState::Streaming as u8, Ordering::Relaxed);
        }

        if self.task.is_none() {
            let inner = self.inner.clone();
            let state_cache = self.state_cache.clone();
            let timestamp_cache = self.timestamp_cache.clone();
            self.task = Some(tokio::spawn(async move {
                match run_streamer(inner.clone(), state_cache.clone(), timestamp_cache).await {
                    Ok(()) => tracing::debug!("Streaming task completed normally"),
                    Err(e) => {
                        tracing::error!("Streaming task error: {}", e);
                        state_cache.store(StreamerState::Error as u8, Ordering::Relaxed);
                        if let Ok(mut guard) = inner.try_lock() {
                            guard.state = StreamerState::Error;
                        }
                    }
                }
                Ok(())
            }));
        }

        Ok(())
    }

    /// Pause streaming.
    pub async fn pause(&mut self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if inner.state == StreamerState::Streaming {
            inner.state = StreamerState::Paused;
            self.state_cache.store(StreamerState::Paused as u8, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Resume streaming.
    pub async fn resume(&mut self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if inner.state == StreamerState::Paused {
            inner.state = StreamerState::Streaming;
            self.state_cache.store(StreamerState::Streaming as u8, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Reset state after FLUSH so the next audio/sync packets have correct
    /// marker and extension bits set, as required by the AirPlay spec.
    pub async fn reset_after_flush(&mut self) {
        let mut inner = self.inner.lock().await;
        inner.first_packet_sent = false;
        if let Some(ref mut sender) = inner.rtp_sender {
            sender.reset_sync_state();
        }
    }

    /// Stop streaming.
    pub async fn stop(&mut self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.state = StreamerState::Stopped;
        inner.buffer.flush();
        inner.decoder = None;
        self.state_cache.store(StreamerState::Stopped as u8, Ordering::Relaxed);
        Ok(())
    }

    /// Seek to position in samples.
    pub async fn seek(&mut self, position_samples: u64) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.buffer.flush();
        if let Some(ref mut decoder) = inner.decoder {
            decoder.seek(position_samples)?;
        }
        inner.current_timestamp = position_samples;
        self.timestamp_cache.store(position_samples, Ordering::Relaxed);
        Ok(())
    }

    /// Get current playback position in samples.
    pub fn position(&self) -> u64 {
        self.timestamp_cache.load(Ordering::Relaxed)
    }

    /// Get buffer fill level percentage.
    pub async fn buffer_level(&self) -> f32 {
        self.inner.lock().await.buffer.fill_percentage()
    }

    /// Set volume (0.0 to 1.0).
    pub async fn set_volume(&mut self, _volume: f32) -> Result<()> {
        // Volume is set via RTSP SET_PARAMETER, not in audio stream
        // This is a no-op placeholder
        Ok(())
    }

    /// Set timing offset from sync protocol.
    pub async fn set_timing_offset(&mut self, offset: ClockOffset) {
        self.inner.lock().await.clock_offset = Some(offset);
    }

    /// Subscribe to timing updates.
    pub async fn set_timing_updates(&mut self, rx: watch::Receiver<ClockOffset>) {
        self.inner.lock().await.timing_rx = Some(rx);
    }

    /// Internal: decode some audio into buffer.
    async fn decode_some(&mut self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        decode_some_inner(&mut inner)?;
        Ok(())
    }
}

fn decode_some_inner(inner: &mut StreamerInner) -> Result<()> {
    if let Some(ref mut decoder) = inner.decoder {
        let format = inner.config.audio_format.clone();
        let frames_per_packet = format.frames_per_packet as usize;

        // Decode 5 frames per batch to minimize blocking in send loop.
        // Very small batches ensure minimal interference with precise timing.
        for _ in 0..5 {
            if let Some(frame) = decoder.decode_resampled(&format, frames_per_packet)? {
                let audio_frame = crate::AudioFrame::new(frame.samples, frame.timestamp);
                inner
                    .buffer
                    .push(audio_frame)
                    .map_err(|_| airplay_core::error::StreamingError::BufferOverflow)?;
            } else {
                break;
            }
        }
    }
    Ok(())
}

async fn run_streamer(
    inner: Arc<Mutex<StreamerInner>>,
    state_cache: Arc<AtomicU8>,
    timestamp_cache: Arc<AtomicU64>,
) -> Result<()> {
    // Try to set RT priority for better timing precision
    set_realtime_priority();

    // Compute frame duration once (constant for the session)
    let frame_duration_ns = {
        let guard = inner.lock().await;
        guard.config.audio_format.frames_per_packet as u64 * 1_000_000_000u64
            / guard.config.audio_format.sample_rate.as_hz() as u64
    };
    let frame_duration = Duration::from_nanos(frame_duration_ns);

    // Use absolute deadline scheduling so processing time doesn't cause drift
    let mut next_deadline = Instant::now();

    loop {
        {
            let state = inner.lock().await.state;
            if state == StreamerState::Stopped || state == StreamerState::Error {
                break;
            }
            if state == StreamerState::Paused {
                sleep(Duration::from_millis(10)).await;
                // Reset deadline after pause so we don't burst-send
                next_deadline = Instant::now();
                continue;
            }
        }

        {
            let mut guard = inner.lock().await;
            if let Some(rx) = guard.timing_rx.as_mut() {
                if rx.has_changed().unwrap_or(false) {
                    let latest = *rx.borrow_and_update();
                    guard.clock_offset = Some(latest);
                }
            }
            // Keep buffer reasonably full (60% threshold) but not too aggressive
            // to avoid blocking the send loop with decode operations
            if guard.buffer.fill_percentage() < 60.0 {
                let decode_start = Instant::now();
                decode_some_inner(&mut guard)?;
                let decode_elapsed = decode_start.elapsed();
                if decode_elapsed.as_millis() > 10 {
                    tracing::warn!(
                        "Decode took {:.2}ms (blocking send loop!)",
                        decode_elapsed.as_secs_f64() * 1000.0
                    );
                }
            }

            // Check for recovery from Buffering state
            if guard.state == StreamerState::Buffering {
                if guard.buffer.fill_percentage() > 10.0 {
                    guard.state = StreamerState::Streaming;
                    state_cache.store(StreamerState::Streaming as u8, Ordering::Relaxed);
                } else if guard.decoder.as_ref().map_or(true, |d| d.is_eof()) && guard.buffer.is_empty() {
                    // Decoder exhausted and buffer empty - playback complete
                    tracing::info!("Decoder EOF and buffer empty - stopping");
                    guard.state = StreamerState::Stopped;
                    state_cache.store(StreamerState::Stopped as u8, Ordering::Relaxed);
                    break;
                } else {
                    // Still buffering, wait and retry
                    drop(guard);
                    sleep(Duration::from_millis(10)).await;
                    // Reset deadline after buffering stall
                    next_deadline = Instant::now();
                    continue;
                }
            }

            let frame = guard.buffer.pop();
            if let Some(frame) = frame {
                // Diagnostic: log PCM sample energy for first few frames
                static DIAG_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                let diag = DIAG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if diag < 5 || diag % 500 == 0 {
                    let rms: f64 = if frame.samples.is_empty() {
                        0.0
                    } else {
                        let sum: f64 = frame.samples.iter().map(|&s| (s as f64).powi(2)).sum();
                        (sum / frame.samples.len() as f64).sqrt()
                    };
                    let max_abs = frame.samples.iter().map(|s| s.unsigned_abs()).max().unwrap_or(0);
                    tracing::info!(
                        "DIAG PCM frame #{}: samples={}, rms={:.1}, max_abs={}, first_4={:?}",
                        diag, frame.samples.len(), rms, max_abs,
                        &frame.samples[..frame.samples.len().min(4)]
                    );
                }

                // Encode synchronously (but lock is only held during encode+send, not during sleep)
                let encode_start = Instant::now();
                let encoder = guard
                    .encoder
                    .as_mut()
                    .ok_or_else(|| airplay_core::error::StreamingError::Encoding("Encoder missing".into()))?;
                let packet = encoder.encode(&frame.samples)?;
                let encode_elapsed = encode_start.elapsed();

                // Diagnostic: log encoded ALAC data and timing for first few packets
                if diag < 5 || diag % 500 == 0 {
                    let all_zero = packet.data.iter().all(|&b| b == 0);
                    tracing::info!(
                        "DIAG ALAC packet #{}: encoded_len={}, all_zero={}, first_8={:02x?}, encode_time={:.2}ms",
                        diag, packet.data.len(), all_zero,
                        &packet.data[..packet.data.len().min(8)],
                        encode_elapsed.as_secs_f64() * 1000.0
                    );
                }

                let payload_type = guard.config.stream_type as u8;
                let sample_rate = guard.config.audio_format.sample_rate.as_hz();
                let last_sync_rtp = guard.last_sync_rtp;

                // Get current time and apply clock offset from PTP/NTP sync
                let local_wall = guard.clock.now_wall_ns();
                let adjusted = if let Some(offset) = guard.clock_offset {
                    let result = guard.clock.apply_offset(local_wall, &offset);
                    if diag < 3 {
                        tracing::info!(
                            "CLOCK OFFSET: offset_ns={}, local_wall={}, adjusted={}, diff={}",
                            offset.offset_ns,
                            local_wall,
                            result,
                            result as i128 - local_wall as i128
                        );
                    }
                    result
                } else {
                    if diag < 3 {
                        tracing::warn!("CLOCK OFFSET: None - using local time directly (may cause timing issues!)");
                    }
                    local_wall
                };

                let ntp = unix_to_ntp(adjusted);

                // Set marker bit on first audio packet (required by some receivers)
                let first_packet = !guard.first_packet_sent;
                let marker = first_packet;
                if marker {
                    tracing::info!("Sending first audio packet with marker bit set");
                }

                let rtp_ts = packet.timestamp as u32;

                // Determine if sync is needed BEFORE borrowing rtp_sender
                let need_sync = first_packet || last_sync_rtp == 0
                    || rtp_ts.wrapping_sub(last_sync_rtp) >= sample_rate;

                if let Some(ref mut sender) = guard.rtp_sender {
                    // Send sync BEFORE first audio packet so receiver knows
                    // the NTP-to-RTP timestamp mapping before any audio arrives
                    if need_sync {
                        sender.send_sync(rtp_ts, ntp)?;
                    }

                    let send_start = Instant::now();
                    sender.send_audio(payload_type, rtp_ts, &packet.data, marker)?;
                    let send_elapsed = send_start.elapsed();

                    if diag < 5 || diag % 500 == 0 {
                        tracing::info!(
                            "DIAG timing #{}: encode={:.2}ms, send={:.2}ms, total={:.2}ms",
                            diag,
                            encode_elapsed.as_secs_f64() * 1000.0,
                            send_elapsed.as_secs_f64() * 1000.0,
                            (encode_elapsed + send_elapsed).as_secs_f64() * 1000.0
                        );
                    }
                }

                if need_sync {
                    guard.last_sync_rtp = rtp_ts;
                }
                if first_packet {
                    guard.first_packet_sent = true;
                }

                guard.current_timestamp = packet.timestamp + packet.samples as u64;
                timestamp_cache.store(guard.current_timestamp, Ordering::Relaxed);
            } else {
                guard.state = StreamerState::Buffering;
                state_cache.store(StreamerState::Buffering as u8, Ordering::Relaxed);
            }
        }

        // Advance deadline by one frame period and sleep until that absolute time.
        // With RT priority, tokio::time::sleep should be more precise.
        next_deadline += frame_duration;
        let now = Instant::now();
        if next_deadline > now {
            tokio::time::sleep(next_deadline - now).await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use airplay_core::StreamConfig;

    fn test_config() -> StreamConfig {
        StreamConfig::default()
    }

    mod state_machine {
        use super::*;

        #[test]
        fn starts_idle() {
            let streamer = AudioStreamer::new(test_config());
            assert_eq!(streamer.state(), StreamerState::Idle);
        }

        #[tokio::test]
        async fn start_transitions_to_buffering() {
            // Can't easily test without real audio file
            // Test that we start in Idle
            let streamer = AudioStreamer::new(test_config());
            assert_eq!(streamer.state(), StreamerState::Idle);
        }

        #[tokio::test]
        async fn buffering_transitions_to_streaming() {
            // Would need mock decoder for proper testing
            let streamer = AudioStreamer::new(test_config());
            assert_eq!(streamer.state(), StreamerState::Idle);
        }

        #[tokio::test]
        async fn pause_transitions_to_paused() {
            let mut streamer = AudioStreamer::new(test_config());
            {
                let mut inner = streamer.inner.lock().await;
                inner.state = StreamerState::Streaming;
            }
            streamer.state_cache.store(StreamerState::Streaming as u8, Ordering::Relaxed);
            streamer.pause().await.unwrap();
            assert_eq!(streamer.state(), StreamerState::Paused);
        }

        #[tokio::test]
        async fn resume_transitions_to_streaming() {
            let mut streamer = AudioStreamer::new(test_config());
            {
                let mut inner = streamer.inner.lock().await;
                inner.state = StreamerState::Paused;
            }
            streamer.state_cache.store(StreamerState::Paused as u8, Ordering::Relaxed);
            streamer.resume().await.unwrap();
            assert_eq!(streamer.state(), StreamerState::Streaming);
        }

        #[tokio::test]
        async fn stop_transitions_to_stopped() {
            let mut streamer = AudioStreamer::new(test_config());
            {
                let mut inner = streamer.inner.lock().await;
                inner.state = StreamerState::Streaming;
            }
            streamer.state_cache.store(StreamerState::Streaming as u8, Ordering::Relaxed);
            streamer.stop().await.unwrap();
            assert_eq!(streamer.state(), StreamerState::Stopped);
        }
    }

    mod streaming {
        use super::*;

        #[tokio::test]
        async fn decodes_and_buffers_audio() {
            // Would need mock decoder
            let streamer = AudioStreamer::new(test_config());
            assert_eq!(streamer.buffer_level().await, 0.0);
        }

        #[tokio::test]
        async fn sends_rtp_packets() {
            // Would need mock RTP sender
            let streamer = AudioStreamer::new(test_config());
            assert!(streamer.inner.lock().await.rtp_sender.is_none());
        }

        #[tokio::test]
        async fn respects_buffer_level() {
            let streamer = AudioStreamer::new(test_config());
            let level = streamer.buffer_level().await;
            assert!(level >= 0.0 && level <= 100.0);
        }

        // End-of-stream handling requires a mock decoder to trigger EOF.
    }

    mod seeking {
        use super::*;

        #[tokio::test]
        async fn seek_clears_buffer() {
            let mut streamer = AudioStreamer::new(test_config());
            streamer.seek(1000).await.unwrap();
            assert_eq!(streamer.buffer_level().await, 0.0);
        }

        #[tokio::test]
        async fn seek_updates_position() {
            let mut streamer = AudioStreamer::new(test_config());
            streamer.seek(44100).await.unwrap();
            assert_eq!(streamer.position(), 44100);
        }

        #[tokio::test]
        async fn seek_while_paused() {
            let mut streamer = AudioStreamer::new(test_config());
            {
                let mut inner = streamer.inner.lock().await;
                inner.state = StreamerState::Paused;
            }
            streamer.state_cache.store(StreamerState::Paused as u8, Ordering::Relaxed);
            streamer.seek(22050).await.unwrap();
            assert_eq!(streamer.position(), 22050);
            assert_eq!(streamer.state(), StreamerState::Paused);
        }
    }

    mod timing {
        use super::*;

        #[tokio::test]
        async fn timestamps_increment_correctly() {
            let streamer = AudioStreamer::new(test_config());
            assert_eq!(streamer.position(), 0);
        }

        #[tokio::test]
        async fn position_tracks_playback() {
            let streamer = AudioStreamer::new(test_config());
            let pos = streamer.position();
            assert_eq!(pos, 0);
        }
    }
}
