//! # airplay-pairing
//!
//! HomeKit and FairPlay authentication for AirPlay 2.
//!
//! This crate implements:
//! - HomeKit pair-setup (SRP-6a based)
//! - HomeKit pair-verify (Curve25519 + Ed25519)
//! - FairPlay authentication (for licensed scenarios)
//! - Transient pairing (no persistent storage)

mod channel;
mod controller;
mod fairplay;
mod pair_setup;
mod pair_verify;
mod session;
mod traits;

pub use channel::EncryptedChannel;
pub use controller::ControllerIdentity;
pub use fairplay::FairPlaySetup;
pub use pair_setup::{PairSetup, TransientPairSetup};
pub use pair_verify::PairVerify;
pub use session::{PairingSession, PairingStep};
pub use traits::{PairingHandler, Transport};
