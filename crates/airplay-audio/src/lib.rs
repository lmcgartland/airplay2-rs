//! # airplay-audio
//!
//! Audio encoding and RTP streaming for AirPlay 2.
//!
//! This crate provides:
//! - Audio decoding from various formats (via symphonia)
//! - Live audio streaming from external sources (e.g., Bluetooth)
//! - ALAC encoding for realtime streaming
//! - AAC encoding for buffered streaming
//! - RTP packet formatting and transmission
//! - Audio buffer management
//! - Retransmission handling

pub mod cipher;
mod decoder;
mod encoder;
mod live_decoder;
mod rtp;
mod buffer;
mod streamer;
mod traits;

pub use decoder::{AudioDecoder, DecodedFrame};
pub use encoder::{AlacEncoder, AacEncoder, AudioEncoder, EncodedPacket, create_encoder};
pub use live_decoder::{LiveAudioDecoder, LiveFrameSender, LivePcmFrame};
pub use rtp::{RtpPacket, RtpSender, RtpReceiver, RtpHeader, RetransmitRequest, build_retransmit_response};
pub use buffer::{AudioBuffer, AudioFrame};
pub use streamer::AudioStreamer;
pub use traits::{AudioSource, EncoderTrait};
