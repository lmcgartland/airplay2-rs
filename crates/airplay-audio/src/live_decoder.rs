//! Live audio decoder for streaming PCM from external sources.
//!
//! This module provides a decoder-like interface for live audio sources
//! (e.g., Bluetooth capture, microphone) that can be used with the existing
//! AudioStreamer pipeline.

use airplay_core::{AudioFormat, error::Result};
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use std::time::Duration;

use crate::decoder::DecodedFrame;

/// Frame of PCM audio sent to the live decoder.
#[derive(Debug, Clone)]
pub struct LivePcmFrame {
    /// Interleaved PCM samples (i16).
    pub samples: Vec<i16>,
    /// Number of channels.
    pub channels: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Sender for pushing live PCM frames to a LiveAudioDecoder.
pub struct LiveFrameSender {
    tx: Sender<LivePcmFrame>,
}

impl LiveFrameSender {
    /// Send a frame of PCM audio.
    ///
    /// Returns true if the frame was sent, false if the channel is full.
    pub fn try_send(&self, frame: LivePcmFrame) -> bool {
        match self.tx.try_send(frame) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                tracing::debug!("Live audio channel full, dropping frame");
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                tracing::debug!("Live audio channel disconnected");
                false
            }
        }
    }

    /// Send a frame, blocking if the channel is full.
    pub fn send(&self, frame: LivePcmFrame) -> bool {
        self.tx.send(frame).is_ok()
    }

    /// Get the channel capacity.
    pub fn capacity(&self) -> Option<usize> {
        self.tx.capacity()
    }

    /// Check if the channel is full.
    pub fn is_full(&self) -> bool {
        self.tx.is_full()
    }
}

/// Live audio decoder that receives PCM from a channel.
///
/// This provides a decoder-like interface compatible with AudioStreamer,
/// allowing live audio sources to be streamed over AirPlay.
pub struct LiveAudioDecoder {
    rx: Receiver<LivePcmFrame>,
    sample_rate: u32,
    channels: u8,
    position_samples: u64,
    eof: bool,
    /// Residual samples from previous decode_resampled call.
    residual_samples: Vec<i16>,
    /// Timeout for receiving frames.
    recv_timeout: Duration,
    /// High-quality sinc resampler (lazily initialized when needed).
    resampler: Option<airplay_resampler::Resampler>,
}

impl LiveAudioDecoder {
    /// Create a new live decoder with the given channel receiver.
    ///
    /// NOTE: The default receive timeout is 5ms to prevent blocking the streamer
    /// loop when the capture catches up. This allows the streamer to continue
    /// running and sending buffered frames even when no new data is available.
    pub fn new(rx: Receiver<LivePcmFrame>, sample_rate: u32, channels: u8) -> Self {
        Self {
            rx,
            sample_rate,
            channels,
            position_samples: 0,
            eof: false,
            residual_samples: Vec::new(),
            recv_timeout: Duration::from_millis(2), // Very short timeout to prevent blocking!
            resampler: None,
        }
    }

    /// Create a live decoder and sender pair.
    ///
    /// The sender can be used to push PCM frames to the decoder.
    /// Channel capacity controls buffering (typically 8-16 frames).
    pub fn create_pair(sample_rate: u32, channels: u8, capacity: usize) -> (LiveFrameSender, Self) {
        let (tx, rx) = bounded::<LivePcmFrame>(capacity);
        let sender = LiveFrameSender { tx };
        let decoder = Self::new(rx, sample_rate, channels);
        (sender, decoder)
    }

    /// Set the receive timeout.
    pub fn set_recv_timeout(&mut self, timeout: Duration) {
        self.recv_timeout = timeout;
    }

    /// Mark the stream as ended (no more frames will be sent).
    pub fn mark_eof(&mut self) {
        self.eof = true;
    }

    /// Get source sample rate.
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Get number of channels.
    pub fn channels(&self) -> u8 {
        self.channels
    }

    /// Get duration in samples (always None for live streams).
    pub fn duration_samples(&self) -> Option<u64> {
        None
    }

    /// Get current position in samples.
    pub fn position_samples(&self) -> u64 {
        self.position_samples
    }

    /// Seek to position (not supported for live streams).
    pub fn seek(&mut self, _position_samples: u64) -> Result<()> {
        Err(airplay_core::error::StreamingError::Encoding(
            "Cannot seek in live audio stream".into(),
        )
        .into())
    }

    /// Decode next frame of audio.
    pub fn decode_frame(&mut self) -> Result<Option<DecodedFrame>> {
        if self.eof {
            return Ok(None);
        }

        match self.rx.recv_timeout(self.recv_timeout) {
            Ok(frame) => {
                let num_frames = frame.samples.len() / frame.channels as usize;
                let decoded = DecodedFrame {
                    samples: frame.samples,
                    channels: frame.channels,
                    sample_rate: frame.sample_rate,
                    timestamp: self.position_samples,
                };
                self.position_samples += num_frames as u64;
                Ok(Some(decoded))
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Timeout - no data available but stream may continue
                tracing::trace!("Live decoder: receive timeout (no data)");
                Ok(None)
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                // Channel disconnected - mark EOF
                tracing::debug!("Live decoder: channel disconnected, marking EOF");
                self.eof = true;
                Ok(None)
            }
        }
    }

    /// Decode and resample to target format.
    ///
    /// This method matches the AudioDecoder interface for compatibility
    /// with AudioStreamer.
    pub fn decode_resampled(
        &mut self,
        target_format: &AudioFormat,
        frames_per_packet: usize,
    ) -> Result<Option<DecodedFrame>> {
        let target_rate = target_format.sample_rate.as_hz();
        let source_rate = self.sample_rate;

        // Initialize resampler lazily if needed
        if source_rate != target_rate && self.resampler.is_none() {
            self.resampler = Some(airplay_resampler::Resampler::new(
                source_rate,
                target_rate,
                self.channels,
            )?);
        }

        // Start with any leftover samples from previous call
        let mut collected_samples = std::mem::take(&mut self.residual_samples);
        let target_samples = frames_per_packet * target_format.channels as usize;

        // Collect frames until we have enough samples
        while collected_samples.len() < target_samples {
            match self.decode_frame()? {
                Some(frame) => {
                    if source_rate == target_rate {
                        collected_samples.extend(frame.samples);
                    } else {
                        // High-quality sinc resampling
                        let resampled = self
                            .resampler
                            .as_mut()
                            .expect("resampler should be initialized")
                            .process(&frame.samples)?;
                        collected_samples.extend(resampled);
                    }
                }
                None => {
                    // No frame available - check if we have any samples
                    if collected_samples.is_empty() {
                        // No residual, no new data - return None
                        return Ok(None);
                    }
                    // Have some residual - pad with silence and return
                    break;
                }
            }
        }

        if collected_samples.is_empty() {
            return Ok(None);
        }

        // Save excess samples for next call
        if collected_samples.len() > target_samples {
            self.residual_samples = collected_samples[target_samples..].to_vec();
            collected_samples.truncate(target_samples);
        } else if collected_samples.len() < target_samples {
            // Pad with silence if we don't have enough
            collected_samples.resize(target_samples, 0);
        }

        // Scale timestamp from source sample rate to target sample rate
        let scaled_timestamp = if source_rate != target_rate {
            (self.position_samples as f64 * target_rate as f64 / source_rate as f64) as u64
        } else {
            self.position_samples
        };

        Ok(Some(DecodedFrame {
            samples: collected_samples,
            channels: target_format.channels,
            sample_rate: target_rate,
            timestamp: scaled_timestamp,
        }))
    }

    /// Check if at end of stream.
    pub fn is_eof(&self) -> bool {
        self.eof && self.rx.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use airplay_core::SampleRate;

    fn test_format() -> AudioFormat {
        AudioFormat {
            codec: airplay_core::AudioCodec::Alac,
            sample_rate: SampleRate::Hz44100,
            bit_depth: 16,
            channels: 2,
            frames_per_packet: 352,
        }
    }

    /// Generate a stereo sine wave for testing.
    fn generate_sine_wave(frequency: f64, sample_rate: u32, num_samples: usize) -> Vec<i16> {
        let mut samples = Vec::with_capacity(num_samples * 2);
        for i in 0..num_samples {
            let t = i as f64 / sample_rate as f64;
            let value = (2.0 * std::f64::consts::PI * frequency * t).sin();
            let sample = (value * 16000.0) as i16; // ~50% amplitude
            samples.push(sample); // Left
            samples.push(sample); // Right
        }
        samples
    }

    #[test]
    fn create_pair_works() {
        let (sender, decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);
        assert_eq!(sender.capacity(), Some(8));
        assert_eq!(decoder.sample_rate(), 44100);
        assert_eq!(decoder.channels(), 2);
    }

    #[test]
    fn send_and_receive_frame() {
        let (sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);

        let frame = LivePcmFrame {
            samples: vec![100i16; 704],
            channels: 2,
            sample_rate: 44100,
        };

        assert!(sender.try_send(frame));

        let decoded = decoder.decode_frame().unwrap();
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.samples.len(), 704);
        assert_eq!(decoded.samples[0], 100);
    }

    #[test]
    fn continuous_streaming_works() {
        // Simulate continuous Bluetooth audio capture
        let (sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 16);
        decoder.set_recv_timeout(Duration::from_millis(50));

        let format = test_format();
        let frames_per_packet = format.frames_per_packet as usize;

        // Send continuous audio (like PipeWire capture)
        // PipeWire sends 1024 frames per period at 44100Hz
        let pipewire_period = 1024;
        let mut total_input_samples = 0;
        let mut total_output_frames = 0;

        // Send 10 periods worth of audio
        for period in 0..10 {
            let sine_samples = generate_sine_wave(440.0, 44100, pipewire_period);
            let frame = LivePcmFrame {
                samples: sine_samples.clone(),
                channels: 2,
                sample_rate: 44100,
            };
            assert!(sender.try_send(frame), "Failed to send period {}", period);
            total_input_samples += pipewire_period;
        }

        // Now decode all available frames
        loop {
            match decoder.decode_resampled(&format, frames_per_packet) {
                Ok(Some(frame)) => {
                    // Verify frame is correct size
                    assert_eq!(
                        frame.samples.len(),
                        frames_per_packet * 2,
                        "Frame has wrong number of samples"
                    );

                    // Verify audio isn't silent (RMS > 0)
                    let rms: f64 = frame
                        .samples
                        .iter()
                        .map(|&s| (s as f64).powi(2))
                        .sum::<f64>()
                        / frame.samples.len() as f64;
                    let rms = rms.sqrt();
                    assert!(rms > 1000.0, "Audio appears silent, RMS = {}", rms);

                    total_output_frames += 1;
                }
                Ok(None) => break,
                Err(e) => panic!("Decode error: {}", e),
            }
        }

        // We sent 10 * 1024 = 10240 frames
        // Each output packet is 352 frames
        // So we should get floor(10240 / 352) = 29 packets
        let expected_packets = total_input_samples / frames_per_packet;
        assert!(
            total_output_frames >= expected_packets - 1 && total_output_frames <= expected_packets + 1,
            "Expected ~{} output frames, got {}",
            expected_packets,
            total_output_frames
        );

        println!(
            "Continuous streaming test: {} input samples -> {} output packets",
            total_input_samples, total_output_frames
        );
    }

    #[test]
    fn decode_produces_non_silent_audio() {
        let (sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);
        decoder.set_recv_timeout(Duration::from_millis(10));

        // Send a 440Hz sine wave
        let samples = generate_sine_wave(440.0, 44100, 1024);
        let frame = LivePcmFrame {
            samples: samples.clone(),
            channels: 2,
            sample_rate: 44100,
        };
        sender.try_send(frame);

        let format = test_format();
        let decoded = decoder.decode_resampled(&format, 352).unwrap().unwrap();

        // Calculate RMS
        let rms: f64 = decoded
            .samples
            .iter()
            .map(|&s| (s as f64).powi(2))
            .sum::<f64>()
            / decoded.samples.len() as f64;
        let rms = rms.sqrt();

        println!("Decoded RMS: {}", rms);
        assert!(rms > 5000.0, "Audio is too quiet, RMS = {}", rms);
    }

    #[test]
    fn residual_samples_preserved_across_calls() {
        let (sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);
        decoder.set_recv_timeout(Duration::from_millis(10));

        // Send a frame larger than what we'll request
        // 1024 stereo samples = 2048 total i16 values
        let frame = LivePcmFrame {
            samples: vec![1234i16; 2048],
            channels: 2,
            sample_rate: 44100,
        };
        sender.try_send(frame);

        let format = test_format();

        // First decode: should get 352 frames
        let decoded1 = decoder.decode_resampled(&format, 352).unwrap().unwrap();
        assert_eq!(decoded1.samples.len(), 704);

        // Second decode: should get next 352 frames from residual
        let decoded2 = decoder.decode_resampled(&format, 352).unwrap().unwrap();
        assert_eq!(decoded2.samples.len(), 704);

        // Third decode: should get remaining ~320 frames (padded with silence)
        // or return None if we don't have enough
    }

    #[test]
    fn decode_resampled_collects_frames() {
        let (sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);
        decoder.set_recv_timeout(Duration::from_millis(10));

        // Send multiple small frames
        for _ in 0..3 {
            let frame = LivePcmFrame {
                samples: vec![1000i16; 300],
                channels: 2,
                sample_rate: 44100,
            };
            sender.try_send(frame);
        }

        let format = test_format();
        let decoded = decoder.decode_resampled(&format, 352).unwrap();
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        // Should have exactly 352 frames * 2 channels = 704 samples
        assert_eq!(decoded.samples.len(), 704);
    }

    #[test]
    fn eof_on_disconnect() {
        let (sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);
        decoder.set_recv_timeout(Duration::from_millis(10));

        drop(sender);

        // Should get None and mark EOF
        let decoded = decoder.decode_frame().unwrap();
        assert!(decoded.is_none());
        assert!(decoder.is_eof());
    }

    #[test]
    fn duration_always_none() {
        let (_sender, decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);
        assert!(decoder.duration_samples().is_none());
    }

    #[test]
    fn seek_returns_error() {
        let (_sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);
        assert!(decoder.seek(1000).is_err());
    }

    /// Test that decoded frames can be encoded with ALAC encoder.
    #[test]
    fn full_encoder_pipeline() {
        use crate::encoder::{create_encoder, AudioEncoder};

        let (sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 16);
        decoder.set_recv_timeout(Duration::from_millis(50));

        let format = test_format();
        let frames_per_packet = format.frames_per_packet as usize;

        // Create ALAC encoder
        let mut encoder = create_encoder(format.clone()).expect("Failed to create encoder");

        // Send 20 periods of audio (enough for multiple packets)
        for _ in 0..20 {
            let samples = generate_sine_wave(440.0, 44100, 1024);
            let frame = LivePcmFrame {
                samples,
                channels: 2,
                sample_rate: 44100,
            };
            sender.try_send(frame);
        }

        // Decode and encode packets
        let mut encoded_count = 0;
        let mut total_encoded_bytes = 0;

        loop {
            match decoder.decode_resampled(&format, frames_per_packet) {
                Ok(Some(frame)) => {
                    // Verify we got the right number of samples
                    assert_eq!(frame.samples.len(), frames_per_packet * 2);

                    // Encode with ALAC
                    match encoder.encode(&frame.samples) {
                        Ok(packet) => {
                            assert!(packet.data.len() > 0, "Encoded packet is empty");
                            assert_eq!(packet.samples, frames_per_packet as u32);
                            total_encoded_bytes += packet.data.len();
                            encoded_count += 1;

                            // ALAC compression ratio is typically 40-60%
                            // Raw size = 352 * 2 channels * 2 bytes = 1408 bytes
                            // Expected encoded: 500-900 bytes
                            assert!(
                                packet.data.len() < 1408,
                                "Encoded packet too large: {} bytes (raw=1408)",
                                packet.data.len()
                            );
                        }
                        Err(e) => panic!("Encode failed: {}", e),
                    }
                }
                Ok(None) => break,
                Err(e) => panic!("Decode error: {}", e),
            }
        }

        println!(
            "Full pipeline test: {} packets encoded, {} total bytes",
            encoded_count, total_encoded_bytes
        );

        // We sent 20 * 1024 = 20480 samples
        // Each packet is 352 samples
        // Expected: ~58 packets (but some may be lost to residual handling)
        assert!(
            encoded_count >= 45,
            "Expected at least 45 packets, got {}",
            encoded_count
        );
    }

    /// Test simulating real Bluetooth capture behavior.
    #[test]
    fn simulated_bluetooth_capture() {
        use std::thread;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let (sender, mut decoder) = LiveAudioDecoder::create_pair(44100, 2, 8);
        decoder.set_recv_timeout(Duration::from_millis(100));

        let format = test_format();
        let frames_per_packet = format.frames_per_packet as usize;

        // Simulate PipeWire capture thread
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let producer = thread::spawn(move || {
            let mut period = 0;
            while running_clone.load(Ordering::Relaxed) && period < 50 {
                // PipeWire sends 1024 frames per period
                let samples = generate_sine_wave(440.0, 44100, 1024);
                let frame = LivePcmFrame {
                    samples,
                    channels: 2,
                    sample_rate: 44100,
                };

                if !sender.try_send(frame) {
                    // Channel full, wait a bit
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }

                period += 1;

                // Simulate ~23ms period (1024 samples at 44100Hz)
                thread::sleep(Duration::from_millis(10));
            }
            println!("Producer sent {} periods", period);
        });

        // Consumer (simulating streamer decode loop)
        let mut decoded_count = 0;
        let start = std::time::Instant::now();

        while start.elapsed() < Duration::from_secs(2) {
            match decoder.decode_resampled(&format, frames_per_packet) {
                Ok(Some(frame)) => {
                    assert_eq!(frame.samples.len(), frames_per_packet * 2);
                    decoded_count += 1;
                }
                Ok(None) => {
                    // No data available, wait a bit
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("Decode error: {}", e),
            }

            if decoded_count >= 100 {
                break;
            }
        }

        running.store(false, Ordering::Relaxed);
        producer.join().unwrap();

        println!("Simulated capture test: decoded {} packets", decoded_count);
        assert!(decoded_count >= 40, "Expected at least 40 packets, got {}", decoded_count);
    }
}
