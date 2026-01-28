//! Now playing / player view.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};
use ratatui::layout::Rect;
use airplay_client::PlaybackState;

use crate::state::AppState;
use crate::ui::format_duration;

/// Render the player view.
pub fn render_player(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Now playing info
            Constraint::Length(3), // Progress bar
            Constraint::Length(5), // Controls / volume
            Constraint::Min(0),    // Empty space
        ])
        .split(area);

    // Now playing info
    render_now_playing(frame, chunks[0], state);

    // Progress bar
    render_progress(frame, chunks[1], state);

    // Volume and controls
    render_controls(frame, chunks[2], state);
}

fn render_now_playing(frame: &mut Frame, area: Rect, state: &AppState) {
    let (title, status_style) = match state.playback_state {
        PlaybackState::Playing => ("▶ Playing", Style::default().fg(Color::Green)),
        PlaybackState::Paused => ("⏸ Paused", Style::default().fg(Color::Yellow)),
        PlaybackState::Stopped => ("⏹ Stopped", Style::default().fg(Color::DarkGray)),
        PlaybackState::Buffering => ("⟳ Buffering", Style::default().fg(Color::Cyan)),
        PlaybackState::Error => ("✕ Error", Style::default().fg(Color::Red)),
    };

    let file_name = state
        .current_file
        .as_ref()
        .map(|f| {
            std::path::Path::new(f)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| f.clone())
        })
        .unwrap_or_else(|| "No file selected".to_string());

    let device_name = state
        .connected_device
        .as_ref()
        .map(|d| d.name.as_str())
        .unwrap_or("Not connected");

    let content = vec![
        Line::from(Span::styled(title, status_style.add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("File: ", Style::default().fg(Color::DarkGray)),
            Span::styled(file_name, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Device: ", Style::default().fg(Color::DarkGray)),
            Span::styled(device_name, Style::default().fg(Color::Cyan)),
        ]),
    ];

    let para = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" Now Playing "))
        .alignment(Alignment::Center);

    frame.render_widget(para, area);
}

fn render_progress(frame: &mut Frame, area: Rect, state: &AppState) {
    let position = state.position;
    let duration = state.duration.unwrap_or(0.0);

    let ratio = if duration > 0.0 {
        (position / duration).min(1.0) as f64
    } else {
        0.0
    };

    let position_str = format_duration(position);
    let duration_str = if duration > 0.0 {
        format_duration(duration)
    } else {
        "--:--".to_string()
    };

    let label = format!("{} / {}", position_str, duration_str);

    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Progress "))
        .gauge_style(
            Style::default()
                .fg(Color::Cyan)
                .bg(Color::DarkGray),
        )
        .ratio(ratio)
        .label(Span::styled(
            label,
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ));

    frame.render_widget(gauge, area);
}

fn render_controls(frame: &mut Frame, area: Rect, state: &AppState) {
    let volume_percent = (state.volume * 100.0) as u16;
    let volume_bar = "█".repeat((volume_percent / 5) as usize);
    let volume_empty = "░".repeat(20 - (volume_percent / 5) as usize);

    let controls = vec![
        Line::from(vec![
            Span::styled("Volume: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&volume_bar, Style::default().fg(Color::Green)),
            Span::styled(&volume_empty, Style::default().fg(Color::DarkGray)),
            Span::styled(format!(" {}%", volume_percent), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Controls: ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Space]", Style::default().fg(Color::Yellow)),
            Span::raw(" Play/Pause  "),
            Span::styled("[s]", Style::default().fg(Color::Yellow)),
            Span::raw(" Stop  "),
            Span::styled("[←/→]", Style::default().fg(Color::Yellow)),
            Span::raw(" Seek  "),
            Span::styled("[+/-]", Style::default().fg(Color::Yellow)),
            Span::raw(" Volume"),
        ]),
    ];

    let para = Paragraph::new(controls)
        .block(Block::default().borders(Borders::ALL).title(" Controls "));

    frame.render_widget(para, area);
}
