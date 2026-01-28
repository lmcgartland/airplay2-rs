//! Main application struct and event loop.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEvent};
use futures::StreamExt;
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn, error, instrument};

use airplay_client::{AirPlayClient, PlaybackState, ClientEvent, CallbackHandler};
use airplay_core::Device;

use crate::action::Action;
use crate::audio_info;
use crate::state::{AppState, View, StatusMessage, DeviceEntry};
use crate::file_browser::FileBrowser;
use crate::ui;

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
        let client = AirPlayClient::with_config(
            Default::default(),
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

        let tx = self.action_tx.clone();
        let client = self.client.clone();
        let path_clone = path.clone();
        tokio::spawn(async move {
            // Use a timeout to prevent indefinite hangs during playback start
            debug!("Calling client.play_file with 30 second timeout");
            let play_result = tokio::time::timeout(Duration::from_secs(30), async {
                let mut client = client.lock().await;
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
