//! Device discovery and list view.

use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};
use ratatui::layout::Rect;

use crate::state::AppState;

/// Render the devices view.
pub fn render_devices(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Connection status
            Constraint::Min(0),    // Device list
        ])
        .split(area);

    // Connection status
    let status_text = if state.scanning {
        Line::from(vec![
            Span::styled("Scanning", Style::default().fg(Color::Yellow)),
            Span::raw("..."),
        ])
    } else if let Some(ref device) = state.connected_device {
        Line::from(vec![
            Span::styled("Connected to: ", Style::default().fg(Color::Green)),
            Span::styled(&device.name, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from(Span::styled(
            "Not connected",
            Style::default().fg(Color::DarkGray),
        ))
    };

    let status = Paragraph::new(status_text)
        .block(Block::default().borders(Borders::ALL).title(" Status "));
    frame.render_widget(status, chunks[0]);

    // Device list
    let items: Vec<ListItem> = state
        .devices
        .iter()
        .map(|entry| {
            let device = &entry.device;
            let connected_marker = if entry.is_connected { " [connected]" } else { "" };
            let selected_marker = if entry.is_selected { " *" } else { "" };

            let style = if entry.is_connected {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            };

            // Extract IPv4 address (prefer IPv4 over IPv6)
            let ipv4_addr = device.addresses.iter()
                .find(|addr| addr.is_ipv4())
                .map(|addr| format!(" ({})", addr))
                .unwrap_or_else(|| String::new());

            let content = Line::from(vec![
                Span::styled(&device.name, style.add_modifier(Modifier::BOLD)),
                Span::styled(ipv4_addr, Style::default().fg(Color::Cyan)),
                Span::styled(connected_marker, Style::default().fg(Color::Green)),
                Span::styled(selected_marker, Style::default().fg(Color::Yellow)),
                Span::raw(" - "),
                Span::styled(&device.model, Style::default().fg(Color::DarkGray)),
            ]);

            ListItem::new(content)
        })
        .collect();

    let title = if state.scanning {
        " Devices (scanning...) "
    } else {
        " Devices "
    };

    let device_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut list_state = ListState::default();
    if !state.devices.is_empty() {
        list_state.select(Some(state.device_index));
    }

    frame.render_stateful_widget(device_list, chunks[1], &mut list_state);
}
