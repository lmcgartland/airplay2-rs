//! Application state management.

use airplay_core::Device;
use airplay_client::{PlaybackState, DeviceGroup};
use std::time::{Duration, Instant};

/// Current view being displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    /// Device discovery and selection.
    #[default]
    Devices,
    /// File browser for selecting audio files.
    Browser,
    /// Now playing / playback controls.
    Player,
    /// Multi-room group management.
    Group,
    /// Bluetooth audio source (Linux only).
    #[cfg(feature = "bluetooth")]
    Bluetooth,
}

impl View {
    /// Get the next view in the cycle.
    pub fn next(self) -> Self {
        match self {
            View::Devices => View::Browser,
            View::Browser => View::Player,
            View::Player => View::Group,
            #[cfg(feature = "bluetooth")]
            View::Group => View::Bluetooth,
            #[cfg(feature = "bluetooth")]
            View::Bluetooth => View::Devices,
            #[cfg(not(feature = "bluetooth"))]
            View::Group => View::Devices,
        }
    }

    /// Get the previous view in the cycle.
    pub fn prev(self) -> Self {
        match self {
            #[cfg(feature = "bluetooth")]
            View::Devices => View::Bluetooth,
            #[cfg(not(feature = "bluetooth"))]
            View::Devices => View::Group,
            View::Browser => View::Devices,
            View::Player => View::Browser,
            View::Group => View::Player,
            #[cfg(feature = "bluetooth")]
            View::Bluetooth => View::Group,
        }
    }

    /// Get display name for the view.
    pub fn name(&self) -> &'static str {
        match self {
            View::Devices => "Devices",
            View::Browser => "Browser",
            View::Player => "Player",
            View::Group => "Group",
            #[cfg(feature = "bluetooth")]
            View::Bluetooth => "Bluetooth",
        }
    }

    /// Get all views in order.
    pub fn all() -> Vec<View> {
        #[cfg(feature = "bluetooth")]
        {
            vec![View::Devices, View::Browser, View::Player, View::Group, View::Bluetooth]
        }
        #[cfg(not(feature = "bluetooth"))]
        {
            vec![View::Devices, View::Browser, View::Player, View::Group]
        }
    }

    /// Get the index of this view in the tab bar.
    pub fn index(&self) -> usize {
        match self {
            View::Devices => 0,
            View::Browser => 1,
            View::Player => 2,
            View::Group => 3,
            #[cfg(feature = "bluetooth")]
            View::Bluetooth => 4,
        }
    }
}

/// Status message with auto-dismiss.
#[derive(Debug, Clone)]
pub struct StatusMessage {
    pub text: String,
    pub is_error: bool,
    pub created_at: Instant,
    pub duration: Duration,
}

impl StatusMessage {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
            created_at: Instant::now(),
            duration: Duration::from_secs(3),
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
            created_at: Instant::now(),
            duration: Duration::from_secs(5),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.duration
    }
}

/// Discovered device with selection state.
#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub device: Device,
    pub is_connected: bool,
    pub is_selected: bool,
}

/// Main application state.
#[derive(Debug)]
pub struct AppState {
    /// Current view.
    pub view: View,
    /// Whether help overlay is shown.
    pub show_help: bool,
    /// Status message (auto-dismisses).
    pub status: Option<StatusMessage>,

    // Device state
    /// Discovered devices.
    pub devices: Vec<DeviceEntry>,
    /// Selected device index in list.
    pub device_index: usize,
    /// Whether device scan is in progress.
    pub scanning: bool,
    /// Connected device (if any).
    pub connected_device: Option<Device>,

    // Playback state
    /// Current playback state.
    pub playback_state: PlaybackState,
    /// Current position in seconds.
    pub position: f64,
    /// Total duration in seconds.
    pub duration: Option<f64>,
    /// Current volume (0.0 to 1.0).
    pub volume: f32,
    /// Current file being played.
    pub current_file: Option<String>,

    // Group state
    /// Current device group.
    pub group: Option<DeviceGroupState>,
    /// Selected index in group member list.
    pub group_member_index: usize,

    // Bluetooth state (Linux only)
    #[cfg(feature = "bluetooth")]
    pub bluetooth: BluetoothState,
}

/// Device group state for UI.
#[derive(Debug, Clone)]
pub struct DeviceGroupState {
    pub leader: Device,
    pub members: Vec<GroupMemberState>,
}

/// Group member state for UI.
#[derive(Debug, Clone)]
pub struct GroupMemberState {
    pub device: Device,
    pub volume: f32,
    pub is_leader: bool,
}

/// Bluetooth state for UI.
#[cfg(feature = "bluetooth")]
#[derive(Debug, Clone)]
pub struct BluetoothState {
    /// System setup status (BlueZ, BlueALSA).
    pub setup_checked: bool,
    /// Whether system is ready for Bluetooth.
    pub setup_ready: bool,
    /// Setup issues to display.
    pub setup_issues: Vec<String>,
    /// Whether Bluetooth adapter is powered.
    pub adapter_powered: bool,
    /// Adapter name (e.g., "hci0").
    pub adapter_name: Option<String>,
    /// Whether scanning for devices.
    pub scanning: bool,
    /// Discovered Bluetooth devices.
    pub devices: Vec<BluetoothDeviceEntry>,
    /// Selected device index.
    pub device_index: usize,
    /// Currently connected A2DP device.
    pub connected_device: Option<BluetoothDeviceEntry>,
    /// Whether streaming audio from Bluetooth.
    pub streaming: bool,
    /// Whether using Bluetooth as audio source for AirPlay.
    pub is_source_active: bool,
    /// Current audio level (RMS, 0.0-1.0).
    pub audio_level: f32,
    /// Total samples received.
    pub samples_received: u64,
}

/// Bluetooth device entry for UI.
#[cfg(feature = "bluetooth")]
#[derive(Debug, Clone)]
pub struct BluetoothDeviceEntry {
    /// Device address.
    pub address: String,
    /// Device name.
    pub name: String,
    /// Whether paired.
    pub paired: bool,
    /// Whether connected.
    pub connected: bool,
    /// Whether trusted.
    pub trusted: bool,
    /// Whether supports A2DP audio source.
    pub supports_a2dp: bool,
    /// Signal strength (RSSI).
    pub rssi: Option<i16>,
}

#[cfg(feature = "bluetooth")]
impl Default for BluetoothState {
    fn default() -> Self {
        Self {
            setup_checked: false,
            setup_ready: false,
            setup_issues: Vec::new(),
            adapter_powered: false,
            adapter_name: None,
            scanning: false,
            devices: Vec::new(),
            device_index: 0,
            connected_device: None,
            streaming: false,
            is_source_active: false,
            audio_level: 0.0,
            samples_received: 0,
        }
    }
}

#[cfg(feature = "bluetooth")]
impl BluetoothState {
    /// Get selected device (if any).
    pub fn selected_device(&self) -> Option<&BluetoothDeviceEntry> {
        self.devices.get(self.device_index)
    }

    /// Move selection up.
    pub fn select_prev(&mut self) {
        if !self.devices.is_empty() && self.device_index > 0 {
            self.device_index -= 1;
        }
    }

    /// Move selection down.
    pub fn select_next(&mut self) {
        if !self.devices.is_empty() && self.device_index < self.devices.len() - 1 {
            self.device_index += 1;
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            view: View::default(),
            show_help: false,
            status: None,
            devices: Vec::new(),
            device_index: 0,
            scanning: false,
            connected_device: None,
            playback_state: PlaybackState::Stopped,
            position: 0.0,
            duration: None,
            volume: 1.0,
            current_file: None,
            group: None,
            group_member_index: 0,
            #[cfg(feature = "bluetooth")]
            bluetooth: BluetoothState::default(),
        }
    }
}

impl AppState {
    /// Create new application state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set status message.
    pub fn set_status(&mut self, msg: StatusMessage) {
        self.status = Some(msg);
    }

    /// Clear expired status message.
    pub fn clear_expired_status(&mut self) {
        if let Some(ref status) = self.status {
            if status.is_expired() {
                self.status = None;
            }
        }
    }

    /// Get selected device (if any).
    pub fn selected_device(&self) -> Option<&Device> {
        self.devices.get(self.device_index).map(|e| &e.device)
    }

    /// Move selection up in current list.
    pub fn select_prev(&mut self) {
        match self.view {
            View::Devices => {
                if !self.devices.is_empty() && self.device_index > 0 {
                    self.device_index -= 1;
                }
            }
            View::Group => {
                if let Some(ref group) = self.group {
                    let count = group.members.len();
                    if count > 0 && self.group_member_index > 0 {
                        self.group_member_index -= 1;
                    }
                }
            }
            #[cfg(feature = "bluetooth")]
            View::Bluetooth => {
                self.bluetooth.select_prev();
            }
            _ => {}
        }
    }

    /// Move selection down in current list.
    pub fn select_next(&mut self) {
        match self.view {
            View::Devices => {
                if !self.devices.is_empty() && self.device_index < self.devices.len() - 1 {
                    self.device_index += 1;
                }
            }
            View::Group => {
                if let Some(ref group) = self.group {
                    let count = group.members.len();
                    if count > 0 && self.group_member_index < count - 1 {
                        self.group_member_index += 1;
                    }
                }
            }
            #[cfg(feature = "bluetooth")]
            View::Bluetooth => {
                self.bluetooth.select_next();
            }
            _ => {}
        }
    }

    /// Update group state from client group.
    pub fn update_group(&mut self, group: Option<&DeviceGroup>) {
        self.group = group.map(|g| {
            DeviceGroupState {
                leader: g.leader().device.clone(),
                members: g.members().map(|m| GroupMemberState {
                    device: m.device.clone(),
                    volume: m.volume,
                    is_leader: m.is_leader,
                }).collect(),
            }
        });
    }
}
