//! Help overlay.

use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::state::AppState;
use crate::ui::centered_rect;

/// Render the help overlay.
pub fn render_help(frame: &mut Frame, _state: &AppState) {
    let area = centered_rect(60, 70, frame.area());

    // Clear the background
    frame.render_widget(Clear, area);

    let help_text = vec![
        Line::from(Span::styled(
            "Keyboard Shortcuts",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled("Navigation", Style::default().fg(Color::Yellow))),
        Line::from(vec![
            Span::styled("  Tab      ", Style::default().fg(Color::Green)),
            Span::raw("Cycle through views"),
        ]),
        Line::from(vec![
            Span::styled("  Esc      ", Style::default().fg(Color::Green)),
            Span::raw("Go back / Cancel"),
        ]),
        Line::from(vec![
            Span::styled("  j/↓      ", Style::default().fg(Color::Green)),
            Span::raw("Move down in list"),
        ]),
        Line::from(vec![
            Span::styled("  k/↑      ", Style::default().fg(Color::Green)),
            Span::raw("Move up in list"),
        ]),
        Line::from(vec![
            Span::styled("  Enter    ", Style::default().fg(Color::Green)),
            Span::raw("Select / Activate"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Devices View", Style::default().fg(Color::Yellow))),
        Line::from(vec![
            Span::styled("  r        ", Style::default().fg(Color::Green)),
            Span::raw("Refresh device list"),
        ]),
        Line::from(vec![
            Span::styled("  Enter    ", Style::default().fg(Color::Green)),
            Span::raw("Connect to device"),
        ]),
        Line::from(""),
        Line::from(Span::styled("File Browser", Style::default().fg(Color::Yellow))),
        Line::from(vec![
            Span::styled("  Enter    ", Style::default().fg(Color::Green)),
            Span::raw("Open folder / Play file"),
        ]),
        Line::from(vec![
            Span::styled("  Backspace", Style::default().fg(Color::Green)),
            Span::raw("Go to parent folder"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Playback", Style::default().fg(Color::Yellow))),
        Line::from(vec![
            Span::styled("  Space    ", Style::default().fg(Color::Green)),
            Span::raw("Play / Pause"),
        ]),
        Line::from(vec![
            Span::styled("  s        ", Style::default().fg(Color::Green)),
            Span::raw("Stop playback"),
        ]),
        Line::from(vec![
            Span::styled("  ← / →    ", Style::default().fg(Color::Green)),
            Span::raw("Seek backward / forward 10s"),
        ]),
        Line::from(vec![
            Span::styled("  + / -    ", Style::default().fg(Color::Green)),
            Span::raw("Volume up / down"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Group View", Style::default().fg(Color::Yellow))),
        Line::from(vec![
            Span::styled("  g        ", Style::default().fg(Color::Green)),
            Span::raw("Create / Open group"),
        ]),
        Line::from(vec![
            Span::styled("  a        ", Style::default().fg(Color::Green)),
            Span::raw("Add device to group"),
        ]),
        Line::from(vec![
            Span::styled("  d        ", Style::default().fg(Color::Green)),
            Span::raw("Remove from group"),
        ]),
        Line::from(vec![
            Span::styled("  x        ", Style::default().fg(Color::Green)),
            Span::raw("Disband group"),
        ]),
        Line::from(""),
        Line::from(Span::styled("General", Style::default().fg(Color::Yellow))),
        Line::from(vec![
            Span::styled("  ?        ", Style::default().fg(Color::Green)),
            Span::raw("Toggle this help"),
        ]),
        Line::from(vec![
            Span::styled("  q        ", Style::default().fg(Color::Green)),
            Span::raw("Quit application"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help ")
                .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .style(Style::default().bg(Color::Black)),
        );

    frame.render_widget(help, area);
}
