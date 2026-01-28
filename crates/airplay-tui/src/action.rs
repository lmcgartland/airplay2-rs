//! Action types for the TUI application.

use airplay_core::Device;
use airplay_client::PlaybackState;
use std::path::PathBuf;

/// Actions that can be dispatched to update state.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Action {
    // Navigation
    /// Quit the application.
    Quit,
    /// Toggle help overlay.
    ToggleHelp,
    /// Switch to next view.
    NextView,
    /// Go back / escape.
    Back,
    /// Move selection up.
    SelectPrev,
    /// Move selection down.
    SelectNext,
    /// Activate selected item.
    Select,

    // Device actions
    /// Start device scan.
    ScanDevices,
    /// Device scan completed with results.
    DevicesScanned(Vec<Device>),
    /// Connect to selected device.
    Connect,
    /// Connect completed.
    Connected(Device),
    /// Disconnect from device.
    Disconnect,
    /// Disconnected from device.
    Disconnected,
    /// Connection/operation failed.
    Error(String),

    // Playback actions
    /// Play/pause toggle.
    PlayPause,
    /// Stop playback.
    Stop,
    /// Seek forward by seconds.
    SeekForward(f64),
    /// Seek backward by seconds.
    SeekBackward(f64),
    /// Increase volume.
    VolumeUp,
    /// Decrease volume.
    VolumeDown,
    /// Set volume to specific value.
    SetVolume(f32),
    /// Playback state changed.
    PlaybackStateChanged(PlaybackState),
    /// Playback started successfully.
    PlaybackStarted,
    /// Position updated.
    PositionUpdated(f64),
    /// Play a file.
    PlayFile(PathBuf),

    // Group actions
    /// Open group view.
    OpenGroup,
    /// Create group from connected device and selected devices.
    CreateGroup,
    /// Add selected device to group.
    AddToGroup,
    /// Remove selected device from group.
    RemoveFromGroup,
    /// Disband current group.
    DisbandGroup,
    /// Group changed.
    GroupChanged,

    // File browser actions
    /// Navigate to directory.
    NavigateDir(PathBuf),
    /// File selected.
    FileSelected(PathBuf),

    // Status
    /// Show status message.
    ShowStatus(String),
    /// Show error message.
    ShowError(String),
    /// Clear status message.
    ClearStatus,
    /// Tick for periodic updates.
    Tick,
}
