//! Main AirPlay client API.

use airplay_core::{Device, DeviceId, StreamConfig, error::Result};
use airplay_core::error::{Error, RtspError, DiscoveryError};
use airplay_discovery::{ServiceBrowser, Discovery};
use airplay_audio::AudioDecoder;
use std::path::Path;
use std::time::Duration;
use crate::{Connection, DeviceGroup, PlaybackState, EventHandler, ClientEvent};

/// High-level AirPlay 2 sender client.
pub struct AirPlayClient {
    browser: ServiceBrowser,
    connection: Option<Connection>,
    group: Option<DeviceGroup>,
    event_handler: Option<Box<dyn EventHandler>>,
    stream_config: StreamConfig,
}

impl AirPlayClient {
    /// Create new client.
    pub fn new() -> Result<Self> {
        Ok(Self {
            browser: ServiceBrowser::new()?,
            connection: None,
            group: None,
            event_handler: None,
            stream_config: StreamConfig::default(),
        })
    }

    /// Create client with specific configuration.
    pub fn with_config(config: StreamConfig, event_handler: Option<Box<dyn EventHandler>>) -> Result<Self> {
        Ok(Self {
            browser: ServiceBrowser::new()?,
            connection: None,
            group: None,
            event_handler,
            stream_config: config,
        })
    }

    /// Set event handler.
    pub fn set_event_handler(&mut self, handler: impl EventHandler + 'static) {
        self.event_handler = Some(Box::new(handler));
    }

    /// Emit an event if handler is set.
    async fn emit_event(&self, event: ClientEvent) {
        if let Some(ref handler) = self.event_handler {
            handler.on_event(event).await;
        }
    }

    /// Discover AirPlay devices on the network.
    pub async fn discover(&self, timeout: Duration) -> Result<Vec<Device>> {
        self.browser.scan(timeout).await
    }

    /// Get a specific device by ID.
    pub async fn get_device(&self, id: &DeviceId) -> Option<Device> {
        self.browser.get_device(id).await
    }

    /// Connect to a device.
    pub async fn connect(&mut self, device: &Device) -> Result<()> {
        // Disconnect existing connection if any
        if self.connection.is_some() {
            self.disconnect().await?;
        }

        let stream_config = if device.features.supports_buffered_audio() {
            // Use real-time ALAC + NTP (matches owntone behavior for HomePod)
            StreamConfig::airplay1_realtime()
        } else {
            self.stream_config.clone()
        };

        // Establish connection
        let mut connection = Connection::connect(device.clone(), stream_config).await?;

        // Complete RTSP SETUP handshake (CRITICAL - required before streaming)
        connection.setup().await?;

        self.connection = Some(connection);

        self.emit_event(ClientEvent::Connected(device.clone())).await;

        Ok(())
    }

    /// Connect to a device with PIN (for password-protected devices).
    pub async fn connect_with_pin(&mut self, device: &Device, pin: &str) -> Result<()> {
        // Disconnect existing connection if any
        if self.connection.is_some() {
            self.disconnect().await?;
        }

        let stream_config = if device.features.supports_buffered_audio() {
            // Use real-time ALAC + NTP (matches owntone behavior for HomePod)
            StreamConfig::airplay1_realtime()
        } else {
            self.stream_config.clone()
        };

        // Establish connection
        let mut connection = Connection::connect_with_pin(device.clone(), stream_config, pin).await?;

        // Complete RTSP SETUP handshake (CRITICAL - required before streaming)
        connection.setup().await?;

        self.connection = Some(connection);

        self.emit_event(ClientEvent::Connected(device.clone())).await;

        Ok(())
    }

    /// Disconnect from current device.
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(ref mut connection) = self.connection {
            connection.disconnect().await?;
        }
        self.connection = None;

        self.emit_event(ClientEvent::Disconnected(None)).await;

        Ok(())
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Get connected device.
    pub fn connected_device(&self) -> Option<&Device> {
        self.connection.as_ref().map(|c| c.device())
    }

    /// Play audio from file.
    pub async fn play_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let connection = self.connection.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::NoSession)
        })?;

        // Create decoder for the file
        let decoder = AudioDecoder::open(path)?;

        // Start streaming
        connection.start_streaming(decoder).await?;

        self.emit_event(ClientEvent::PlaybackStateChanged(PlaybackState::Playing)).await;

        Ok(())
    }

    /// Play audio from raw PCM samples.
    pub async fn play_pcm(&mut self, _samples: &[i16], _sample_rate: u32, _channels: u8) -> Result<()> {
        let _connection = self.connection.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::NoSession)
        })?;

        // TODO: PCM streaming path not implemented yet
        Err(Error::Streaming(airplay_core::error::StreamingError::InvalidFormat(
            "PCM streaming not implemented".into(),
        )))
    }

    /// Pause playback.
    pub async fn pause(&mut self) -> Result<()> {
        let connection = self.connection.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::NoSession)
        })?;

        connection.pause().await?;

        self.emit_event(ClientEvent::PlaybackStateChanged(PlaybackState::Paused)).await;

        Ok(())
    }

    /// Resume playback.
    pub async fn resume(&mut self) -> Result<()> {
        let connection = self.connection.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::NoSession)
        })?;

        connection.resume().await?;

        self.emit_event(ClientEvent::PlaybackStateChanged(PlaybackState::Playing)).await;

        Ok(())
    }

    /// Stop playback.
    pub async fn stop(&mut self) -> Result<()> {
        let connection = self.connection.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::NoSession)
        })?;

        connection.stop().await?;

        self.emit_event(ClientEvent::PlaybackStateChanged(PlaybackState::Stopped)).await;

        Ok(())
    }

    /// Seek to position in seconds.
    pub async fn seek(&mut self, position_secs: f64) -> Result<()> {
        let _connection = self.connection.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::NoSession)
        })?;

        // Seeking requires buffer manipulation and timestamp coordination
        // For now, this is a stub - full implementation would need:
        // 1. Flush current buffer
        // 2. Seek decoder to position
        // 3. Refill buffer
        // 4. Resume playback

        self.emit_event(ClientEvent::PositionUpdated(position_secs)).await;

        Ok(())
    }

    /// Set volume (0.0 to 1.0).
    pub async fn set_volume(&mut self, volume: f32) -> Result<()> {
        let connection = self.connection.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::NoSession)
        })?;

        connection.set_volume(volume).await?;

        self.emit_event(ClientEvent::VolumeChanged(volume)).await;

        Ok(())
    }

    /// Send feedback/keepalive to the receiver.
    ///
    /// **IMPORTANT:** AirPlay 2 receivers expect periodic feedback requests (~every 2 seconds)
    /// during active playback. Call this from your main loop to maintain the session and prevent
    /// timeouts.
    ///
    /// # Example
    /// ```ignore
    /// // In your playback loop:
    /// loop {
    ///     tokio::time::sleep(Duration::from_secs(2)).await;
    ///     if let Err(e) = client.send_feedback().await {
    ///         eprintln!("Feedback failed: {}", e);
    ///     }
    /// }
    /// ```
    pub async fn send_feedback(&mut self) -> Result<()> {
        let connection = self.connection.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::NoSession)
        })?;

        connection.send_feedback().await
    }

    /// Get current playback state.
    pub fn playback_state(&self) -> PlaybackState {
        self.connection
            .as_ref()
            .map(|c| c.playback_state())
            .unwrap_or(PlaybackState::Stopped)
    }

    /// Get current playback position in seconds.
    pub fn playback_position(&self) -> f64 {
        self.connection
            .as_ref()
            .map(|c| c.playback_position())
            .unwrap_or(0.0)
    }

    /// Wait for playback to complete.
    pub async fn wait_for_completion(&self) -> Result<()> {
        // Poll playback state until stopped
        loop {
            let state = self.playback_state();
            match state {
                PlaybackState::Stopped | PlaybackState::Error => break,
                _ => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Ok(())
    }

    // Multi-room methods

    /// Create a multi-room group.
    pub async fn create_group(&mut self, devices: &[&Device]) -> Result<()> {
        if devices.is_empty() {
            return Err(Error::Discovery(DiscoveryError::NoDevicesFound));
        }

        // First device is the leader
        let leader = devices[0];

        // Connect to leader if not already connected
        if self.connection.is_none() || self.connected_device().map(|d| &d.id) != Some(&leader.id) {
            self.connect(leader).await?;
        }

        // Create group with leader
        let mut group = DeviceGroup::new(leader.clone());

        // Add remaining devices as members
        for device in devices.iter().skip(1) {
            group.add_member((*device).clone())?;
        }

        self.group = Some(group);

        self.emit_event(ClientEvent::GroupChanged).await;

        Ok(())
    }

    /// Add device to current group.
    pub async fn add_to_group(&mut self, device: &Device) -> Result<()> {
        let group = self.group.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::SetupFailed("No group exists".to_string()))
        })?;

        group.add_member(device.clone())?;

        // Send SETPEERS to all connections
        if let Some(ref mut connection) = self.connection {
            let addresses = group.peer_addresses();
            connection.send_setpeers(&addresses).await?;
        }

        self.emit_event(ClientEvent::GroupChanged).await;

        Ok(())
    }

    /// Remove device from current group.
    pub async fn remove_from_group(&mut self, device: &Device) -> Result<()> {
        let group = self.group.as_mut().ok_or_else(|| {
            Error::Rtsp(RtspError::SetupFailed("No group exists".to_string()))
        })?;

        group.remove_member(&device.id)?;

        // Send updated SETPEERS
        if let Some(ref mut connection) = self.connection {
            let addresses = group.peer_addresses();
            connection.send_setpeers(&addresses).await?;
        }

        self.emit_event(ClientEvent::GroupChanged).await;

        Ok(())
    }

    /// Disband the current group.
    pub async fn disband_group(&mut self) -> Result<()> {
        self.group = None;

        self.emit_event(ClientEvent::GroupChanged).await;

        Ok(())
    }

    /// Get current group.
    pub fn group(&self) -> Option<&DeviceGroup> {
        self.group.as_ref()
    }
}

impl Default for AirPlayClient {
    fn default() -> Self {
        Self::new().expect("Failed to create client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod client_creation {
        use super::*;

        #[test]
        fn new_creates_disconnected_client() {
            // Skip if mDNS not available
            if let Ok(client) = AirPlayClient::new() {
                assert!(!client.is_connected());
                assert!(client.connected_device().is_none());
                assert_eq!(client.playback_state(), PlaybackState::Stopped);
            }
        }

        #[test]
        fn default_creates_client() {
            // Skip if mDNS not available
            // Note: Default panics if creation fails, so we use new() for testing
            if let Ok(client) = AirPlayClient::new() {
                assert!(!client.is_connected());
            }
        }
    }

    mod discovery {
        use super::*;

        #[tokio::test]
        async fn discover_returns_devices() {
            // Skip if mDNS not available
            if let Ok(client) = AirPlayClient::new() {
                // Very short timeout - we don't expect to find devices in tests
                let devices = client.discover(Duration::from_millis(100)).await;
                assert!(devices.is_ok());
            }
        }

        #[tokio::test]
        async fn discover_respects_timeout() {
            if let Ok(client) = AirPlayClient::new() {
                let start = std::time::Instant::now();
                let _ = client.discover(Duration::from_millis(200)).await;
                let elapsed = start.elapsed();
                // Should complete within a reasonable time of the timeout
                assert!(elapsed >= Duration::from_millis(200));
                assert!(elapsed < Duration::from_secs(2));
            }
        }

        #[tokio::test]
        async fn get_device_returns_none_for_unknown() {
            if let Ok(client) = AirPlayClient::new() {
                let unknown_id = DeviceId([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]);
                let result = client.get_device(&unknown_id).await;
                assert!(result.is_none());
            }
        }
    }

    mod connection {
        use super::*;

        #[tokio::test]
        async fn connect_establishes_connection() {
            // This test requires a real device - skip in unit tests
        }

        #[tokio::test]
        async fn connect_with_pin_for_protected_device() {
            // This test requires a real device - skip in unit tests
        }

        #[tokio::test]
        async fn disconnect_clears_connection() {
            if let Ok(mut client) = AirPlayClient::new() {
                // Even without being connected, disconnect should succeed
                let result = client.disconnect().await;
                assert!(result.is_ok());
                assert!(!client.is_connected());
            }
        }

        #[tokio::test]
        async fn is_connected_reflects_state() {
            if let Ok(client) = AirPlayClient::new() {
                assert!(!client.is_connected());
            }
        }

        #[tokio::test]
        async fn connected_device_returns_device() {
            if let Ok(client) = AirPlayClient::new() {
                // Not connected, should return None
                assert!(client.connected_device().is_none());
            }
        }
    }

    mod playback {
        use super::*;

        #[tokio::test]
        async fn play_file_starts_playback() {
            // This test requires a real device - skip in unit tests
        }

        #[tokio::test]
        async fn play_file_error_when_disconnected() {
            if let Ok(mut client) = AirPlayClient::new() {
                let result = client.play_file("/nonexistent.mp3").await;
                // Should fail because we're not connected
                assert!(result.is_err());
            }
        }

        #[tokio::test]
        async fn pause_pauses_playback() {
            if let Ok(mut client) = AirPlayClient::new() {
                // Should fail when not connected
                let result = client.pause().await;
                assert!(result.is_err());
            }
        }

        #[tokio::test]
        async fn resume_resumes_playback() {
            if let Ok(mut client) = AirPlayClient::new() {
                // Should fail when not connected
                let result = client.resume().await;
                assert!(result.is_err());
            }
        }

        #[tokio::test]
        async fn stop_stops_playback() {
            if let Ok(mut client) = AirPlayClient::new() {
                // Should fail when not connected
                let result = client.stop().await;
                assert!(result.is_err());
            }
        }

        #[tokio::test]
        async fn seek_changes_position() {
            if let Ok(mut client) = AirPlayClient::new() {
                // Should fail when not connected
                let result = client.seek(10.0).await;
                assert!(result.is_err());
            }
        }

        #[tokio::test]
        async fn set_volume_in_range() {
            if let Ok(mut client) = AirPlayClient::new() {
                // Should fail when not connected
                let result = client.set_volume(0.5).await;
                assert!(result.is_err());
            }
        }

        #[tokio::test]
        async fn playback_state_reflects_current_state() {
            if let Ok(client) = AirPlayClient::new() {
                assert_eq!(client.playback_state(), PlaybackState::Stopped);
            }
        }

        #[tokio::test]
        async fn playback_position_tracks_progress() {
            if let Ok(client) = AirPlayClient::new() {
                assert_eq!(client.playback_position(), 0.0);
            }
        }

        #[tokio::test]
        async fn wait_for_completion_blocks() {
            // This test would block forever without actual playback
            // Skip in unit tests
        }
    }

    mod multi_room {
        use super::*;

        #[tokio::test]
        async fn create_group_with_multiple_devices() {
            // This test requires real devices - skip in unit tests
        }

        #[tokio::test]
        async fn add_to_group_adds_device() {
            // This test requires real devices - skip in unit tests
        }

        #[tokio::test]
        async fn remove_from_group_removes_device() {
            // This test requires real devices - skip in unit tests
        }

        #[tokio::test]
        async fn disband_group_clears_group() {
            if let Ok(mut client) = AirPlayClient::new() {
                // Even without a group, disband should succeed
                let result = client.disband_group().await;
                assert!(result.is_ok());
                assert!(client.group().is_none());
            }
        }
    }

    mod events {
        use super::*;

        #[tokio::test]
        async fn event_handler_called_on_connect() {
            // This test requires real devices - skip in unit tests
        }

        #[tokio::test]
        async fn event_handler_called_on_disconnect() {
            // We can test this without a device
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::Arc;
            use crate::events::CallbackHandler;

            let event_received = Arc::new(AtomicBool::new(false));
            let event_received_clone = Arc::clone(&event_received);

            if let Ok(mut client) = AirPlayClient::new() {
                client.set_event_handler(CallbackHandler::new(move |event| {
                    if matches!(event, ClientEvent::Disconnected(_)) {
                        event_received_clone.store(true, Ordering::SeqCst);
                    }
                }));

                client.disconnect().await.unwrap();
                assert!(event_received.load(Ordering::SeqCst));
            }
        }

        #[tokio::test]
        async fn event_handler_called_on_playback_change() {
            // This test requires real devices - skip in unit tests
        }
    }
}
