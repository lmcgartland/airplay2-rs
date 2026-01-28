//! # airplay-audio
//!
//! Audio encoding and RTP streaming for AirPlay 2.
//!
//! This crate provides:
//! - Audio decoding from various formats (via symphonia)
//! - ALAC encoding for realtime streaming
//! - AAC encoding for buffered streaming
//! - RTP packet formatting and transmission
//! - Audio buffer management
//! - Retransmission handling

pub mod cipher;
mod decoder;
mod encoder;
mod rtp;
mod buffer;
mod streamer;
mod traits;

pub use decoder::AudioDecoder;
pub use encoder::{AlacEncoder, AacEncoder, AudioEncoder, EncodedPacket};
pub use rtp::{RtpPacket, RtpSender, RtpReceiver, RtpHeader, RetransmitRequest, build_retransmit_response};
pub use buffer::{AudioBuffer, AudioFrame};
pub use streamer::AudioStreamer;
pub use traits::{AudioSource, EncoderTrait};
