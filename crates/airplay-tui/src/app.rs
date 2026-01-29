//! Main application struct and event loop.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(all(feature = "bluetooth", target_os = "linux"))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEvent};
use futures::StreamExt;
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn, error, instrument};

use airplay_client::{AirPlayClient, PlaybackState, ClientEvent, CallbackHandler, EqConfig};
#[cfg(all(feature = "bluetooth", target_os = "linux"))]
use airplay_client::{LiveFrameSender, LivePcmFrame};
use airplay_core::{Device, StreamConfig};

use crate::action::Action;
use crate::audio_info;
#[cfg(feature = "bluetooth")]
use crate::bluetooth_helper;
use crate::state::{AppState, View, StatusMessage, DeviceEntry};
use crate::file_browser::FileBrowser;
use crate::ui;

#[cfg(all(feature = "bluetooth", target_os = "linux"))]
use airplay_bluetooth::{
    start_capture, CaptureConfig, calculate_rms,
};

/// Shared state for the Bluetooth capture forwarding thread.
#[cfg(all(feature = "bluetooth", target_os = "linux"))]
struct BtCaptureShared {
    /// Flag to stop the capture thread.
    stop: AtomicBool,
    /// Current audio level (RMS) for UI display.
    audio_level: std::sync::atomic::AtomicU32,
    /// Total samples captured for UI display.
    samples_received: AtomicU64,
}

/// Write a diagnostic WAV file (16-bit stereo).
#[cfg(all(feature = "bluetooth", target_os = "linux"))]
fn write_diagnostic_wav(path: &str, samples: &[i16], sample_rate: u32) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;

    let num_samples = samples.len() / 2; // stereo frames
    let num_channels = 2u16;
    let bits_per_sample = 16u16;
    let byte_rate = sample_rate * num_channels as u32 * bits_per_sample as u32 / 8;
    let block_align = num_channels * bits_per_sample / 8;
    let data_size = (samples.len() * 2) as u32; // total bytes
    let file_size = 36 + data_size;

    let mut file = File::create(path)?;

    // RIFF header
    file.write_all(b"RIFF")?;
    file.write_all(&file_size.to_le_bytes())?;
    file.write_all(b"WAVE")?;

    // fmt chunk
    file.write_all(b"fmt ")?;
    file.write_all(&16u32.to_le_bytes())?; // chunk size
    file.write_all(&1u16.to_le_bytes())?; // audio format (PCM)
    file.write_all(&num_channels.to_le_bytes())?;
    file.write_all(&sample_rate.to_le_bytes())?;
    file.write_all(&byte_rate.to_le_bytes())?;
    file.write_all(&block_align.to_le_bytes())?;
    file.write_all(&bits_per_sample.to_le_bytes())?;

    // data chunk
    file.write_all(b"data")?;
    file.write_all(&data_size.to_le_bytes())?;

    // Write samples (already interleaved)
    for &sample in samples {
        file.write_all(&sample.to_le_bytes())?;
    }

    tracing::info!("Diagnostic WAV: {} frames, {} Hz, {} bytes", num_samples, sample_rate, data_size);
    Ok(())
}

/// Main application.
pub struct App {
    /// Application state.
    state: AppState,
    /// File browser state.
    browser: FileBrowser,
    /// AirPlay client.
    client: Arc<Mutex<AirPlayClient>>,
    /// Action sender for async operations.
    action_tx: mpsc::UnboundedSender<Action>,
    /// Action receiver.
    action_rx: mpsc::UnboundedReceiver<Action>,
    /// Whether the app should quit.
    should_quit: bool,
    /// Last time feedback was sent to receiver (for periodic keepalive).
    last_feedback_time: Instant,
    /// Bluetooth capture shared state for communication with capture thread.
    #[cfg(all(feature = "bluetooth", target_os = "linux"))]
    bt_capture_shared: Option<Arc<BtCaptureShared>>,
    /// Bluetooth capture thread handle.
    #[cfg(all(feature = "bluetooth", target_os = "linux"))]
    bt_capture_thread: Option<std::thread::JoinHandle<()>>,
}

impl App {
    /// Create new application.
    #[instrument(name = "App::new")]
    pub fn new() -> Result<Self> {
        info!("Creating new App instance");
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        // Create client with event handler that dispatches to our action channel
        let tx = action_tx.clone();
        debug!("Creating AirPlay client");
        // Use realtime mode with NTP timing for reliable playback
        let client = AirPlayClient::with_config(
            StreamConfig::airplay1_realtime(),
            Some(Box::new(CallbackHandler::new(move |event| {
                let action = match event {
                    ClientEvent::DeviceDiscovered(_device) => {
                        // Handled by scan completion
                        return;
                    }
                    ClientEvent::Connected(device) => {
                        info!("Client event: Connected to {}", device.name);
                        Action::Connected(device)
                    }
                    ClientEvent::Disconnected(reason) => {
                        info!("Client event: Disconnected, reason: {:?}", reason);
                        if let Some(r) = reason {
                            let _ = tx.send(Action::ShowError(r));
                        }
                        Action::Disconnected
                    }
                    ClientEvent::PlaybackStateChanged(state) => {
                        debug!("Client event: Playback state changed to {:?}", state);
                        Action::PlaybackStateChanged(state)
                    }
                    ClientEvent::PositionUpdated(pos) => Action::PositionUpdated(pos),
                    ClientEvent::VolumeChanged(vol) => Action::SetVolume(vol),
                    ClientEvent::Error(e) => {
                        error!("Client event: Error - {}", e);
                        Action::Error(e)
                    }
                    ClientEvent::GroupChanged => Action::GroupChanged,
                    _ => return,
                };
                let _ = tx.send(action);
            }))),
        )?;
        let client = Arc::new(Mutex::new(client));

        info!("App created successfully");
        Ok(Self {
            state: AppState::new(),
            browser: FileBrowser::default(),
            client,
            action_tx,
            action_rx,
            should_quit: false,
            last_feedback_time: Instant::now(),
            #[cfg(all(feature = "bluetooth", target_os = "linux"))]
            bt_capture_shared: None,
            #[cfg(all(feature = "bluetooth", target_os = "linux"))]
            bt_capture_thread: None,
        })
    }

    /// Run the application main loop.
    #[instrument(skip(self, terminal), name = "App::run")]
    pub async fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        info!("Starting main event loop");

        // Initial device scan
        self.dispatch(Action::ScanDevices);

        // Create event stream for keyboard input
        let mut event_stream = crossterm::event::EventStream::new();

        // Tick interval for periodic updates
        let mut tick_interval = tokio::time::interval(Duration::from_millis(250));

        loop {
            // Draw UI
            terminal.draw(|frame| {
                ui::render(frame, &self.state, &self.browser);
            })?;

            // Handle events
            tokio::select! {
                // Keyboard input
                event = event_stream.next() => {
                    if let Some(Ok(Event::Key(key))) = event {
                        debug!("Key event: {:?}", key.code);
                        if let Some(action) = self.handle_key(key) {
                            debug!("Dispatching action: {:?}", action);
                            self.dispatch(action);
                        }
                    }
                }

                // Action from async operations or event handler
                Some(action) = self.action_rx.recv() => {
                    debug!("Handling action: {:?}", action);
                    self.handle_action(action).await;
                }

                // Periodic tick
                _ = tick_interval.tick() => {
                    self.dispatch(Action::Tick);
                }
            }

            if self.should_quit {
                info!("Quit requested, exiting main loop");
                break;
            }
        }

        Ok(())
    }

    /// Map key event to action.
    fn handle_key(&self, key: KeyEvent) -> Option<Action> {
        // Handle help overlay first
        if self.state.show_help {
            return Some(Action::ToggleHelp);
        }

        match key.code {
            // Global keys
            KeyCode::Char('q') => Some(Action::Quit),
            KeyCode::Char('?') => Some(Action::ToggleHelp),
            KeyCode::Tab => Some(Action::NextView),
            KeyCode::Esc => Some(Action::Back),

            // Navigation
            KeyCode::Up | KeyCode::Char('k') => Some(Action::SelectPrev),
            KeyCode::Down | KeyCode::Char('j') => Some(Action::SelectNext),
            KeyCode::Enter => Some(Action::Select),

            // View-specific keys
            _ => self.handle_view_key(key),
        }
    }

    /// Handle view-specific key bindings.
    fn handle_view_key(&self, key: KeyEvent) -> Option<Action> {
        match self.state.view {
            View::Devices => match key.code {
                KeyCode::Char('r') => Some(Action::ScanDevices),
                _ => None,
            },
            View::Browser => match key.code {
                KeyCode::Backspace => {
                    Some(Action::NavigateDir(
                        self.browser.current_dir.parent()
                            .unwrap_or(&self.browser.current_dir)
                            .to_path_buf()
                    ))
                }
                _ => None,
            },
            View::Player => match key.code {
                KeyCode::Char(' ') => Some(Action::PlayPause),
                KeyCode::Char('s') => Some(Action::Stop),
                KeyCode::Left => Some(Action::SeekBackward(10.0)),
                KeyCode::Right => Some(Action::SeekForward(10.0)),
                KeyCode::Char('+') | KeyCode::Char('=') => Some(Action::VolumeUp),
                KeyCode::Char('-') => Some(Action::VolumeDown),
                // EQ controls - intuitive keys
                KeyCode::Char('e') => Some(Action::EqToggleExpanded),
                KeyCode::Char('b') => Some(Action::EqToggleBypass),
                KeyCode::Char('r') => Some(Action::EqReset),
                // Band selection: , and . (like < > without shift)
                KeyCode::Char(',') => Some(Action::EqSelectPrevBand),
                KeyCode::Char('.') => Some(Action::EqSelectNextBand),
                // Gain adjustment: [ and ] (down/up like volume)
                KeyCode::Char('[') => Some(Action::EqDecreaseGain),
                KeyCode::Char(']') => Some(Action::EqIncreaseGain),
                // Also support < > for gain (shifted , .)
                KeyCode::Char('<') => Some(Action::EqDecreaseGain),
                KeyCode::Char('>') => Some(Action::EqIncreaseGain),
                _ => None,
            },
            View::Group => match key.code {
                KeyCode::Char('g') => Some(Action::CreateGroup),
                KeyCode::Char('a') => Some(Action::AddToGroup),
                KeyCode::Char('d') => Some(Action::RemoveFromGroup),
                KeyCode::Char('x') => Some(Action::DisbandGroup),
                KeyCode::Char('+') | KeyCode::Char('=') => Some(Action::VolumeUp),
                KeyCode::Char('-') => Some(Action::VolumeDown),
                _ => None,
            },
            #[cfg(feature = "bluetooth")]
            View::Bluetooth => match key.code {
                KeyCode::Char('s') => Some(Action::BluetoothScan),
                KeyCode::Char('p') => Some(Action::BluetoothPair),
                KeyCode::Char('c') => Some(Action::BluetoothConnect),
                KeyCode::Char('d') => Some(Action::BluetoothDisconnect),
                KeyCode::Char('u') => Some(Action::BluetoothStartSource),
                KeyCode::Char('i') => Some(Action::BluetoothAutoInstall),
                _ => None,
            },
        }
    }

    /// Dispatch an action.
    fn dispatch(&self, action: Action) {
        let _ = self.action_tx.send(action);
    }

    /// Handle an action.
    async fn handle_action(&mut self, action: Action) {
        match action {
            // Navigation
            Action::Quit => {
                self.should_quit = true;
            }
            Action::ToggleHelp => {
                self.state.show_help = !self.state.show_help;
            }
            Action::NextView => {
                self.state.view = self.state.view.next();
                debug!("Switched to view: {:?}", self.state.view);

                // Check Bluetooth setup when first entering Bluetooth view
                #[cfg(feature = "bluetooth")]
                if self.state.view == View::Bluetooth && !self.state.bluetooth.setup_checked {
                    self.dispatch(Action::BluetoothCheckSetup);
                }
            }
            Action::Back => {
                if self.state.view != View::Devices {
                    self.state.view = self.state.view.prev();
                    debug!("Switched to view: {:?}", self.state.view);
                }
            }
            Action::SelectPrev => {
                match self.state.view {
                    View::Browser => self.browser.select_prev(),
                    _ => self.state.select_prev(),
                }
            }
            Action::SelectNext => {
                match self.state.view {
                    View::Browser => self.browser.select_next(),
                    _ => self.state.select_next(),
                }
            }
            Action::Select => {
                debug!("Select action in view: {:?}", self.state.view);
                self.handle_select().await;
            }

            // Device actions
            Action::ScanDevices => {
                info!("Starting device scan");
                self.scan_devices().await;
            }
            Action::DevicesScanned(devices) => {
                info!("Device scan complete, found {} devices", devices.len());
                self.state.scanning = false;
                self.state.devices = devices
                    .into_iter()
                    .map(|device| {
                        let is_connected = self.state.connected_device
                            .as_ref()
                            .map(|d| d.id == device.id)
                            .unwrap_or(false);
                        DeviceEntry {
                            device,
                            is_connected,
                            is_selected: false,
                        }
                    })
                    .collect();
                if self.state.device_index >= self.state.devices.len() {
                    self.state.device_index = 0;
                }
            }
            Action::Connect => {
                self.connect_to_selected().await;
            }
            Action::Connected(device) => {
                info!("Connected to device: {}", device.name);
                self.state.connected_device = Some(device.clone());
                self.state.set_status(StatusMessage::info(format!(
                    "Connected to {}",
                    device.name
                )));
                // Update device list to show connection status
                for entry in &mut self.state.devices {
                    entry.is_connected = entry.device.id == device.id;
                }
            }
            Action::Disconnect => {
                info!("Disconnecting from device");
                let mut client = self.client.lock().await;
                if let Err(e) = client.disconnect().await {
                    error!("Disconnect failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Disconnect failed: {}",
                        e
                    )));
                }
            }
            Action::Disconnected => {
                info!("Disconnected from device");
                self.state.connected_device = None;
                self.state.playback_state = PlaybackState::Stopped;
                for entry in &mut self.state.devices {
                    entry.is_connected = false;
                }
                self.state.set_status(StatusMessage::info("Disconnected"));
            }
            Action::Error(e) => {
                error!("Error: {}", e);
                self.state.set_status(StatusMessage::error(e));
            }

            // Playback actions
            Action::PlayPause => {
                debug!("Play/pause toggle, current state: {:?}", self.state.playback_state);
                self.toggle_playback().await;
            }
            Action::Stop => {
                info!("Stopping playback");
                let mut client = self.client.lock().await;
                if let Err(e) = client.stop().await {
                    error!("Stop failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Stop failed: {}",
                        e
                    )));
                } else {
                    // Reset playback state
                    self.state.position = 0.0;
                    self.state.duration = None;
                }
            }
            Action::SeekForward(secs) => {
                let new_pos = self.state.position + secs;
                debug!("Seeking forward to {}", new_pos);
                let mut client = self.client.lock().await;
                if let Err(e) = client.seek(new_pos).await {
                    error!("Seek failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Seek failed: {}",
                        e
                    )));
                }
            }
            Action::SeekBackward(secs) => {
                let new_pos = (self.state.position - secs).max(0.0);
                debug!("Seeking backward to {}", new_pos);
                let mut client = self.client.lock().await;
                if let Err(e) = client.seek(new_pos).await {
                    error!("Seek failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Seek failed: {}",
                        e
                    )));
                }
            }
            Action::VolumeUp => {
                let new_vol = (self.state.volume + 0.05).min(1.0);
                debug!("Volume up to {}", new_vol);
                let mut client = self.client.lock().await;
                if let Err(e) = client.set_volume(new_vol).await {
                    error!("Volume change failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Volume change failed: {}",
                        e
                    )));
                } else {
                    self.state.volume = new_vol;
                }
            }
            Action::VolumeDown => {
                let new_vol = (self.state.volume - 0.05).max(0.0);
                debug!("Volume down to {}", new_vol);
                let mut client = self.client.lock().await;
                if let Err(e) = client.set_volume(new_vol).await {
                    error!("Volume change failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Volume change failed: {}",
                        e
                    )));
                } else {
                    self.state.volume = new_vol;
                }
            }
            Action::SetVolume(vol) => {
                self.state.volume = vol;
            }
            Action::PlaybackStateChanged(state) => {
                debug!("Playback state changed: {:?}", state);
                self.state.playback_state = state;
            }
            Action::PlaybackStarted => {
                info!("Playback started");
                self.state.view = View::Player;
                self.state.set_status(StatusMessage::info("Playback started"));
            }
            Action::PositionUpdated(pos) => {
                self.state.position = pos;
            }
            Action::PlayFile(path) => {
                info!("Play file action: {:?}", path);
                self.play_file(path).await;
            }

            // Group actions
            Action::OpenGroup => {
                self.state.view = View::Group;
            }
            Action::CreateGroup => {
                info!("Creating group");
                self.create_group().await;
            }
            Action::AddToGroup => {
                info!("Adding device to group");
                self.add_to_group().await;
            }
            Action::RemoveFromGroup => {
                info!("Removing device from group");
                self.remove_from_group().await;
            }
            Action::DisbandGroup => {
                info!("Disbanding group");
                let mut client = self.client.lock().await;
                if let Err(e) = client.disband_group().await {
                    error!("Disband failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Disband failed: {}",
                        e
                    )));
                } else {
                    self.state.group = None;
                    self.state.set_status(StatusMessage::info("Group disbanded"));
                }
            }
            Action::GroupChanged => {
                debug!("Group changed");
                let client = self.client.lock().await;
                self.state.update_group(client.group());
            }

            // File browser actions
            Action::NavigateDir(path) => {
                info!("Navigating to directory: {:?}", path);
                self.browser.navigate(&path);
            }
            Action::FileSelected(path) => {
                info!("File selected: {:?}", path);
                self.play_file(path).await;
            }

            // Status
            Action::ShowStatus(msg) => {
                debug!("Status: {}", msg);
                self.state.set_status(StatusMessage::info(msg));
            }
            Action::ShowError(msg) => {
                warn!("Error status: {}", msg);
                self.state.set_status(StatusMessage::error(msg));
            }
            Action::ClearStatus => {
                self.state.status = None;
            }
            // Equalizer actions
            Action::EqSelectPrevBand => {
                self.state.eq.select_prev_band();
            }
            Action::EqSelectNextBand => {
                self.state.eq.select_next_band();
            }
            Action::EqIncreaseGain => {
                self.state.eq.increase_gain();
            }
            Action::EqDecreaseGain => {
                self.state.eq.decrease_gain();
            }
            Action::EqToggleBypass => {
                self.state.eq.toggle_bypass();
                let status = if self.state.eq.is_bypassed() {
                    "EQ bypassed"
                } else {
                    "EQ enabled"
                };
                self.state.set_status(StatusMessage::info(status));
            }
            Action::EqToggleExpanded => {
                self.state.eq.toggle_expanded();
            }
            Action::EqReset => {
                self.state.eq.reset();
                self.state.set_status(StatusMessage::info("EQ reset to flat"));
            }

            Action::Tick => {
                self.state.clear_expired_status();

                // Update playback position and state
                if let Ok(mut client) = self.client.try_lock() {
                    self.state.position = client.playback_position();
                    self.state.playback_state = client.playback_state();

                    // Send feedback every ~2 seconds during playback to maintain session
                    if self.state.playback_state == PlaybackState::Playing {
                        let now = Instant::now();
                        if now.duration_since(self.last_feedback_time) >= Duration::from_secs(2) {
                            if let Err(e) = client.send_feedback().await {
                                warn!("Feedback failed: {}", e);
                            } else {
                                debug!("Feedback sent successfully");
                            }
                            self.last_feedback_time = now;
                        }
                    }
                }

                // Update Bluetooth UI from capture thread's shared state (Linux only)
                #[cfg(all(feature = "bluetooth", target_os = "linux"))]
                if self.state.bluetooth.is_source_active {
                    if let Some(ref shared) = self.bt_capture_shared {
                        // Read audio level from shared state (set by capture thread)
                        let level_scaled = shared.audio_level.load(Ordering::Relaxed);
                        self.state.bluetooth.audio_level = level_scaled as f32 / 1000.0;
                        self.state.bluetooth.samples_received = shared.samples_received.load(Ordering::Relaxed);

                        // Check if capture thread stopped (stop flag set externally or error)
                        if shared.stop.load(Ordering::Relaxed) {
                            // Thread signaled stop, check if it's still running
                            if self.bt_capture_thread.as_ref().map_or(true, |h| h.is_finished()) {
                                warn!("Bluetooth capture thread stopped");
                                self.bt_capture_shared = None;
                                self.bt_capture_thread = None;
                                self.state.bluetooth.is_source_active = false;
                                self.state.bluetooth.streaming = false;
                                self.state.set_status(StatusMessage::error("Audio capture stopped"));
                            }
                        }
                    }
                }
            }

            // Bluetooth actions (Linux only)
            #[cfg(feature = "bluetooth")]
            Action::BluetoothCheckSetup => {
                debug!("Checking Bluetooth setup");

                let mut issues = Vec::new();

                // Check Bluetooth service
                if !bluetooth_helper::is_bluetooth_running().await {
                    issues.push("Bluetooth service not running (sudo systemctl start bluetooth)".to_string());
                }

                // Check BlueALSA
                if !bluetooth_helper::is_bluealsa_running().await {
                    issues.push("BlueALSA not running (sudo systemctl start bluealsa)".to_string());
                }

                self.state.bluetooth.setup_checked = true;
                self.state.bluetooth.setup_ready = issues.is_empty();
                self.state.bluetooth.setup_issues = issues;

                if self.state.bluetooth.setup_ready {
                    // Auto-initialize adapter and scan for paired devices
                    self.dispatch(Action::BluetoothInitAdapter);
                }
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothAutoInstall => {
                info!("Attempting automatic Bluetooth setup");
                self.state.set_status(StatusMessage::info("Please start services manually:"));
                self.state.bluetooth.setup_issues = vec![
                    "sudo systemctl start bluetooth".to_string(),
                    "sudo systemctl start bluealsa".to_string(),
                ];
                // Re-check setup after showing instructions
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let _ = tx.send(Action::BluetoothCheckSetup);
                });
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothInitAdapter => {
                debug!("Initializing Bluetooth adapter");

                self.state.bluetooth.adapter_powered = true;
                self.state.bluetooth.adapter_name = Some("hci0".to_string());

                // Load paired devices automatically
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                                        let devices: Vec<crate::state::BluetoothDeviceEntry> =
                        bluetooth_helper::get_paired_devices().await;
                    info!("Found {} paired devices", devices.len());
                    let _ = tx.send(Action::BluetoothDevicesScanned(devices));
                });
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothAdapterReady { name, powered } => {
                self.state.bluetooth.adapter_name = Some(name);
                self.state.bluetooth.adapter_powered = powered;
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothScan => {
                info!("Starting Bluetooth scan");
                self.state.bluetooth.scanning = true;
                self.state.set_status(StatusMessage::info("Scanning for Bluetooth devices..."));

                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    
                    // Start a background scan (10 seconds)
                    let _ = bluetooth_helper::start_scan().await;

                    // Wait for scan to complete
                    tokio::time::sleep(Duration::from_secs(5)).await;

                    // Get all discovered devices
                    let devices: Vec<crate::state::BluetoothDeviceEntry> =
                        bluetooth_helper::get_discovered_devices().await;
                    info!("Scan found {} devices", devices.len());

                    let _ = tx.send(Action::BluetoothDevicesScanned(devices));
                    let _ = tx.send(Action::ShowStatus("Scan complete".to_string()));
                });
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothDevicesScanned(devices) => {
                self.state.bluetooth.scanning = false;
                self.state.bluetooth.devices = devices;
                if self.state.bluetooth.device_index >= self.state.bluetooth.devices.len() {
                    self.state.bluetooth.device_index = 0;
                }
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothPair => {
                if let Some(device) = self.state.bluetooth.selected_device().cloned() {
                    info!("Pairing with {}", device.name);
                    self.state.set_status(StatusMessage::info(format!("Pairing with {}...", device.name)));

                    let tx = self.action_tx.clone();
                    let address = device.address.clone();
                    let name = device.name.clone();
                    tokio::spawn(async move {
                        
                        match bluetooth_helper::pair_device(&address).await {
                            Ok(()) => {
                                let _ = tx.send(Action::ShowStatus(format!("Paired with {}", name)));
                                // Refresh device list
                                let devices: Vec<crate::state::BluetoothDeviceEntry> =
                                    bluetooth_helper::get_discovered_devices().await;
                                let _ = tx.send(Action::BluetoothDevicesScanned(devices));
                            }
                            Err(e) => {
                                let _ = tx.send(Action::BluetoothError(e));
                            }
                        }
                    });
                }
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothConnect => {
                if let Some(device) = self.state.bluetooth.selected_device().cloned() {
                    info!("Connecting to {}", device.name);
                    self.state.set_status(StatusMessage::info(format!("Connecting to {}...", device.name)));

                    let tx = self.action_tx.clone();
                    let address = device.address.clone();
                    let name = device.name.clone();
                    tokio::spawn(async move {
                        
                        match bluetooth_helper::connect_device(&address).await {
                            Ok(()) => {
                                // Wait a moment for BlueALSA to detect the audio stream
                                tokio::time::sleep(Duration::from_secs(2)).await;

                                // Check if audio stream is active
                                let has_audio = bluetooth_helper::has_active_audio_stream(&address).await;

                                let entry = crate::state::BluetoothDeviceEntry {
                                    address,
                                    name: name.clone(),
                                    paired: true,
                                    connected: true,
                                    trusted: true,
                                    supports_a2dp: has_audio,
                                    rssi: None,
                                };

                                let _ = tx.send(Action::BluetoothConnected(entry));
                                if has_audio {
                                    let _ = tx.send(Action::ShowStatus(format!("Connected to {} (audio streaming)", name)));
                                } else {
                                    let _ = tx.send(Action::ShowStatus(format!("Connected to {} (no audio yet - start playing)", name)));
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Action::BluetoothError(e));
                            }
                        }
                    });
                }
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothConnected(device) => {
                info!("Connected to Bluetooth device: {}", device.name);
                self.state.bluetooth.connected_device = Some(device.clone());
                self.state.set_status(StatusMessage::info(format!("Connected to {}", device.name)));
                // Update device list to show connection status
                for entry in &mut self.state.bluetooth.devices {
                    entry.connected = entry.address == device.address;
                }
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothDisconnect => {
                if let Some(ref device) = self.state.bluetooth.connected_device.clone() {
                    info!("Disconnecting from {}", device.name);
                    self.state.set_status(StatusMessage::info(format!("Disconnecting from {}...", device.name)));

                    let tx = self.action_tx.clone();
                    let address = device.address.clone();
                    tokio::spawn(async move {
                        
                        match bluetooth_helper::disconnect_device(&address).await {
                            Ok(()) => {
                                let _ = tx.send(Action::BluetoothDisconnected);
                            }
                            Err(e) => {
                                let _ = tx.send(Action::BluetoothError(e));
                            }
                        }
                    });
                } else {
                    self.dispatch(Action::BluetoothDisconnected);
                }
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothDisconnected => {
                self.state.bluetooth.connected_device = None;
                self.state.bluetooth.streaming = false;
                self.state.bluetooth.is_source_active = false;
                for entry in &mut self.state.bluetooth.devices {
                    entry.connected = false;
                }
                self.state.set_status(StatusMessage::info("Bluetooth disconnected"));
            }

            #[cfg(all(feature = "bluetooth", target_os = "linux"))]
            Action::BluetoothStartSource => {
                if let Some(ref device) = self.state.bluetooth.connected_device.clone() {
                    // First check if we're connected to an AirPlay device
                    let client_connected = {
                        let client = self.client.lock().await;
                        client.is_connected()
                    };

                    if !client_connected {
                        self.state.set_status(StatusMessage::error("Connect to an AirPlay device first"));
                        return;
                    }

                    info!("Starting Bluetooth audio source from {}", device.address);

                    // Stop any existing capture thread
                    if let Some(ref shared) = self.bt_capture_shared {
                        shared.stop.store(true, Ordering::Relaxed);
                    }
                    if let Some(handle) = self.bt_capture_thread.take() {
                        let _ = handle.join();
                    }
                    self.bt_capture_shared = None;

                    // Start BlueALSA capture (using HD config for aptX HD turntable)
                    let config = CaptureConfig::for_bluealsa_hd(&device.address);
                    match start_capture(config) {
                        Ok(mut capture) => {
                            info!("BlueALSA capture started successfully");

                            // Create sender/decoder pair FIRST with larger buffer for pre-fill
                            // 64 frames @ ~23ms each = ~1.5 seconds of buffer capacity
                            use airplay_client::LiveAudioDecoder;
                            let (sender, decoder) = LiveAudioDecoder::create_pair(44100, 2, 64);

                            // Create shared state for capture thread
                            let shared = Arc::new(BtCaptureShared {
                                stop: AtomicBool::new(false),
                                audio_level: std::sync::atomic::AtomicU32::new(0),
                                samples_received: AtomicU64::new(0),
                            });
                            let shared_clone = Arc::clone(&shared);

                            // Spawn capture thread BEFORE starting streaming
                            // This allows frames to flow into the decoder's channel
                            let thread = std::thread::Builder::new()
                                .name("bt-capture".into())
                                .spawn(move || {
                                    info!("Bluetooth capture thread started");
                                    let mut total_frames_sent = 0u64;

                                    while !shared_clone.stop.load(Ordering::Relaxed) {
                                        match capture.recv_timeout(Duration::from_millis(50)) {
                                            Ok(frame) => {
                                                let rms = calculate_rms(&frame.samples);
                                                shared_clone.audio_level.store(
                                                    (rms * 1000.0) as u32,
                                                    Ordering::Relaxed
                                                );

                                                let samples = frame.samples.len() / 2;
                                                shared_clone.samples_received.fetch_add(
                                                    samples as u64,
                                                    Ordering::Relaxed
                                                );

                                                let live_frame = LivePcmFrame {
                                                    samples: frame.samples,
                                                    channels: 2,
                                                    sample_rate: 44100,
                                                };

                                                if sender.try_send(live_frame) {
                                                    total_frames_sent += 1;
                                                    if total_frames_sent % 100 == 0 {
                                                        debug!("Sent {} frames to AirPlay", total_frames_sent);
                                                    }
                                                } else if sender.is_full() {
                                                    debug!("Live sender channel full, dropping frame");
                                                }
                                            }
                                            Err(airplay_bluetooth::BluetoothError::Timeout) => {
                                                // No data available, continue
                                            }
                                            Err(e) => {
                                                error!("Capture error: {}", e);
                                                break;
                                            }
                                        }
                                    }

                                    info!("Bluetooth capture thread stopping, sent {} frames", total_frames_sent);
                                    capture.stop();
                                })
                                .expect("Failed to spawn capture thread");

                            // Wait for channel to pre-fill before starting streaming
                            // This ensures the streamer has audio data when it starts
                            info!("Waiting for capture buffer to pre-fill...");
                            std::thread::sleep(Duration::from_millis(500));
                            info!("Pre-fill complete, starting AirPlay streaming");

                            // Now start streaming with the pre-filled decoder
                            // Set a moderate render delay (500ms) for live streaming to give
                            // the AirPlay receiver time to build its jitter buffer
                            let stream_result = {
                                let mut client = self.client.lock().await;
                                client.set_render_delay_ms(500);
                                // Set up EQ for live streaming
                                let eq_config = self.state.eq.config.clone();
                                let eq_params = Arc::clone(&self.state.eq.params);
                                if let Err(e) = client.set_eq_params(eq_config, eq_params) {
                                    warn!("Failed to set EQ params for live streaming: {}", e);
                                }
                                client.start_live_streaming_with_decoder(decoder).await
                            };

                            match stream_result {
                                Ok(()) => {
                                    info!("Live AirPlay streaming started successfully");
                                    self.bt_capture_shared = Some(shared);
                                    self.bt_capture_thread = Some(thread);
                                    self.state.bluetooth.is_source_active = true;
                                    self.state.bluetooth.streaming = true;
                                    self.state.bluetooth.samples_received = 0;
                                    self.state.set_status(StatusMessage::info(format!(
                                        "Streaming {} → AirPlay",
                                        device.name
                                    )));
                                }
                                Err(e) => {
                                    error!("Failed to start live streaming: {}", e);
                                    // Stop the capture thread since streaming failed
                                    shared.stop.store(true, Ordering::Relaxed);
                                    let _ = thread.join();
                                    self.state.set_status(StatusMessage::error(format!(
                                        "Failed to start streaming: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to start BlueALSA capture: {}", e);
                            self.state.set_status(StatusMessage::error(format!(
                                "Failed to start capture: {}. Make sure device is playing audio.",
                                e
                            )));
                        }
                    }
                } else {
                    self.state.set_status(StatusMessage::error("No Bluetooth device connected"));
                }
            }

            #[cfg(all(feature = "bluetooth", not(target_os = "linux")))]
            Action::BluetoothStartSource => {
                self.state.set_status(StatusMessage::error("Bluetooth audio source only supported on Linux"));
            }

            #[cfg(all(feature = "bluetooth", target_os = "linux"))]
            Action::BluetoothStopSource => {
                info!("Stopping Bluetooth audio source");

                // Signal capture thread to stop
                if let Some(ref shared) = self.bt_capture_shared {
                    shared.stop.store(true, Ordering::Relaxed);
                }

                // Wait for thread to finish
                if let Some(handle) = self.bt_capture_thread.take() {
                    let _ = handle.join();
                }
                self.bt_capture_shared = None;

                // Stop AirPlay playback
                {
                    let mut client = self.client.lock().await;
                    if let Err(e) = client.stop().await {
                        warn!("Failed to stop AirPlay playback: {}", e);
                    }
                }

                self.state.bluetooth.is_source_active = false;
                self.state.bluetooth.streaming = false;
                self.state.set_status(StatusMessage::info("Bluetooth audio source stopped"));
            }

            #[cfg(all(feature = "bluetooth", not(target_os = "linux")))]
            Action::BluetoothStopSource => {
                self.state.bluetooth.is_source_active = false;
                self.state.bluetooth.streaming = false;
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothAudioLevel { level, samples } => {
                self.state.bluetooth.audio_level = level;
                self.state.bluetooth.samples_received = samples;
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothStreamingStatus(is_streaming) => {
                self.state.bluetooth.streaming = is_streaming;
            }

            #[cfg(feature = "bluetooth")]
            Action::BluetoothError(e) => {
                error!("Bluetooth error: {}", e);
                self.state.set_status(StatusMessage::error(e));
            }
        }
    }

    /// Handle select action based on current view.
    #[instrument(skip(self), name = "handle_select")]
    async fn handle_select(&mut self) {
        match self.state.view {
            View::Devices => {
                info!("Selecting device");
                self.connect_to_selected().await;
            }
            View::Browser => {
                debug!("Browser select, current entry: {:?}",
                    self.browser.selected_entry().map(|e| &e.name));
                if let Some(path) = self.browser.activate() {
                    info!("Playing file from browser: {:?}", path);
                    self.play_file(path).await;
                }
            }
            View::Player => {
                debug!("Player select - toggle playback");
                self.toggle_playback().await;
            }
            View::Group => {
                // Toggle device selection for group creation
                if let Some(entry) = self.state.devices.get_mut(self.state.device_index) {
                    entry.is_selected = !entry.is_selected;
                    debug!("Toggled device selection: {} = {}", entry.device.name, entry.is_selected);
                }
            }
            #[cfg(feature = "bluetooth")]
            View::Bluetooth => {
                // Connect to selected Bluetooth device
                if self.state.bluetooth.selected_device().is_some() {
                    self.dispatch(Action::BluetoothConnect);
                }
            }
        }
    }

    /// Scan for AirPlay devices.
    #[instrument(skip(self), name = "scan_devices")]
    async fn scan_devices(&mut self) {
        self.state.scanning = true;
        self.state.set_status(StatusMessage::info("Scanning for devices..."));

        let tx = self.action_tx.clone();

        info!("Starting device discovery (5 second timeout)");

        // Spawn scan task
        let client = self.client.lock().await;
        match client.discover(Duration::from_secs(5)).await {
            Ok(devices) => {
                info!("Discovery complete, found {} devices", devices.len());
                for device in &devices {
                    debug!("  - {} ({})", device.name, device.model);
                }
                let _ = tx.send(Action::DevicesScanned(devices));
                let _ = tx.send(Action::ShowStatus("Scan complete".to_string()));
            }
            Err(e) => {
                error!("Discovery failed: {}", e);
                let _ = tx.send(Action::DevicesScanned(vec![]));
                let _ = tx.send(Action::ShowError(format!("Scan failed: {}", e)));
            }
        }
    }

    /// Connect to selected device.
    #[instrument(skip(self), name = "connect_to_selected")]
    async fn connect_to_selected(&mut self) {
        if let Some(device) = self.state.selected_device().cloned() {
            info!("Connecting to device: {} at {:?}", device.name, device.addresses);
            self.state.set_status(StatusMessage::info(format!(
                "Connecting to {}...",
                device.name
            )));

            // Use a timeout to prevent indefinite hangs
            let connect_result = tokio::time::timeout(
                Duration::from_secs(30),
                async {
                    let mut client = self.client.lock().await;
                    client.connect(&device).await
                }
            ).await;

            match connect_result {
                Ok(Ok(())) => {
                    info!("Connection successful");
                }
                Ok(Err(e)) => {
                    error!("Connection failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Connection failed: {}",
                        e
                    )));
                }
                Err(_) => {
                    error!("Connection timed out after 30 seconds");
                    self.state.set_status(StatusMessage::error(
                        "Connection timed out"
                    ));
                }
            }
        } else {
            warn!("No device selected for connection");
        }
    }

    /// Toggle play/pause.
    #[instrument(skip(self), name = "toggle_playback")]
    async fn toggle_playback(&mut self) {
        match self.state.playback_state {
            PlaybackState::Playing => {
                info!("Pausing playback");
                let mut client = self.client.lock().await;
                if let Err(e) = client.pause().await {
                    error!("Pause failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Pause failed: {}",
                        e
                    )));
                }
            }
            PlaybackState::Paused => {
                info!("Resuming playback");
                let mut client = self.client.lock().await;
                if let Err(e) = client.resume().await {
                    error!("Resume failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Resume failed: {}",
                        e
                    )));
                }
            }
            _ => {
                debug!("Toggle playback ignored, state: {:?}", self.state.playback_state);
            }
        }
    }

    /// Play an audio file.
    #[instrument(skip(self), name = "play_file", fields(path = %path.display()))]
    async fn play_file(&mut self, path: PathBuf) {
        info!("play_file called with path: {:?}", path);

        let is_connected = {
            let client = self.client.lock().await;
            client.is_connected()
        };

        if !is_connected {
            warn!("Cannot play file - not connected to device");
            self.state.set_status(StatusMessage::error(
                "Not connected to a device",
            ));
            return;
        }

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());

        // Extract audio duration for progress display
        let duration = audio_info::get_audio_duration(&path);
        if let Some(dur) = duration {
            debug!("Audio duration: {:.1}s", dur);
            self.state.duration = Some(dur);
        } else {
            debug!("Could not determine audio duration");
            self.state.duration = None;
        }

        info!("Starting playback of: {}", file_name);
        self.state.set_status(StatusMessage::info(format!(
            "Playing {}...",
            file_name
        )));
        self.state.current_file = Some(path.display().to_string());

        // Get EQ params to pass to the streamer
        let eq_config = self.state.eq.config.clone();
        let eq_params = Arc::clone(&self.state.eq.params);

        let tx = self.action_tx.clone();
        let client = self.client.clone();
        let path_clone = path.clone();
        tokio::spawn(async move {
            // Use a timeout to prevent indefinite hangs during playback start
            debug!("Calling client.play_file with 30 second timeout");
            let play_result = tokio::time::timeout(Duration::from_secs(30), async {
                let mut client = client.lock().await;
                // Set up EQ before starting playback
                if let Err(e) = client.set_eq_params(eq_config, eq_params) {
                    warn!("Failed to set EQ params: {}", e);
                } else {
                    info!("EQ params configured for playback");
                }
                client.play_file(&path_clone).await
            })
            .await;

            match play_result {
                Ok(Ok(())) => {
                    info!("Playback started successfully");
                    let _ = tx.send(Action::PlaybackStarted);
                }
                Ok(Err(e)) => {
                    error!("Playback failed: {}", e);
                    let _ = tx.send(Action::ShowError(format!(
                        "Playback failed: {}",
                        e
                    )));
                }
                Err(_) => {
                    error!("Playback start timed out after 30 seconds");
                    let _ = tx.send(Action::ShowError(
                        "Playback start timed out".to_string(),
                    ));
                }
            }
        });
    }

    /// Create a multi-room group.
    #[instrument(skip(self), name = "create_group")]
    async fn create_group(&mut self) {
        // Get connected device and selected devices
        let connected = match &self.state.connected_device {
            Some(d) => d.clone(),
            None => {
                warn!("Cannot create group - not connected to device");
                self.state.set_status(StatusMessage::error(
                    "Connect to a device first",
                ));
                return;
            }
        };

        let selected: Vec<Device> = self
            .state
            .devices
            .iter()
            .filter(|e| e.is_selected && e.device.id != connected.id)
            .map(|e| e.device.clone())
            .collect();

        if selected.is_empty() {
            warn!("No devices selected for group");
            self.state.set_status(StatusMessage::error(
                "Select additional devices for the group",
            ));
            return;
        }

        info!("Creating group with {} members", selected.len() + 1);

        // Create group with connected device as leader
        let mut devices: Vec<&Device> = vec![&connected];
        devices.extend(selected.iter());

        let mut client = self.client.lock().await;
        if let Err(e) = client.create_group(&devices).await {
            error!("Group creation failed: {}", e);
            self.state.set_status(StatusMessage::error(format!(
                "Group creation failed: {}",
                e
            )));
        } else {
            info!("Group created successfully");
            self.state.update_group(client.group());
            self.state.set_status(StatusMessage::info("Group created"));
            // Clear selections
            for entry in &mut self.state.devices {
                entry.is_selected = false;
            }
        }
    }

    /// Add selected device to group.
    #[instrument(skip(self), name = "add_to_group")]
    async fn add_to_group(&mut self) {
        let mut client = self.client.lock().await;
        if client.group().is_none() {
            warn!("Cannot add to group - no group exists");
            self.state.set_status(StatusMessage::error("No group exists"));
            return;
        }

        if let Some(device) = self.state.selected_device().cloned() {
            info!("Adding {} to group", device.name);
            if let Err(e) = client.add_to_group(&device).await {
                error!("Add to group failed: {}", e);
                self.state.set_status(StatusMessage::error(format!(
                    "Add to group failed: {}",
                    e
                )));
            } else {
                info!("Device added to group");
                self.state.update_group(client.group());
                self.state.set_status(StatusMessage::info(format!(
                    "Added {} to group",
                    device.name
                )));
            }
        }
    }

    /// Remove selected member from group.
    #[instrument(skip(self), name = "remove_from_group")]
    async fn remove_from_group(&mut self) {
        if let Some(ref group) = self.state.group {
            if let Some(member) = group.members.get(self.state.group_member_index) {
                let device = member.device.clone();
                info!("Removing {} from group", device.name);
                let mut client = self.client.lock().await;
                if let Err(e) = client.remove_from_group(&device).await {
                    error!("Remove from group failed: {}", e);
                    self.state.set_status(StatusMessage::error(format!(
                        "Remove failed: {}",
                        e
                    )));
                } else {
                    info!("Device removed from group");
                    self.state.update_group(client.group());
                    self.state.set_status(StatusMessage::info(format!(
                        "Removed {} from group",
                        device.name
                    )));
                }
            }
        }
    }
}
