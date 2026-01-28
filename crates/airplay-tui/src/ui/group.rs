//! Multi-room group management view.

use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};
use ratatui::layout::Rect;

use crate::state::AppState;

/// Render the group management view.
pub fn render_group(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Group info
            Constraint::Min(0),    // Member list
            Constraint::Length(4), // Actions help
        ])
        .split(area);

    // Group info
    render_group_info(frame, chunks[0], state);

    // Member list
    render_member_list(frame, chunks[1], state);

    // Actions help
    render_group_actions(frame, chunks[2], state);
}

fn render_group_info(frame: &mut Frame, area: Rect, state: &AppState) {
    let content = if let Some(ref group) = state.group {
        vec![
            Line::from(vec![
                Span::styled("Group Active", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Leader: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&group.leader.name, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Members: ", Style::default().fg(Color::DarkGray)),
                Span::styled(group.members.len().to_string(), Style::default().fg(Color::White)),
            ]),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "No Group",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "Connect to a device and press 'g' to create a group",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    };

    let para = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" Multi-Room Group "));

    frame.render_widget(para, area);
}

fn render_member_list(frame: &mut Frame, area: Rect, state: &AppState) {
    let items: Vec<ListItem> = if let Some(ref group) = state.group {
        group
            .members
            .iter()
            .map(|member| {
                let leader_marker = if member.is_leader { " [leader]" } else { "" };
                let volume_percent = (member.volume * 100.0) as u16;

                let content = Line::from(vec![
                    Span::styled(
                        &member.device.name,
                        if member.is_leader {
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        },
                    ),
                    Span::styled(leader_marker, Style::default().fg(Color::Yellow)),
                    Span::raw(" - "),
                    Span::styled(
                        format!("Vol: {}%", volume_percent),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]);

                ListItem::new(content)
            })
            .collect()
    } else {
        // Show available devices for group creation
        state
            .devices
            .iter()
            .map(|entry| {
                let connected_marker = if entry.is_connected { " [connected]" } else { "" };

                let content = Line::from(vec![
                    Span::styled(
                        &entry.device.name,
                        if entry.is_connected {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default()
                        },
                    ),
                    Span::styled(connected_marker, Style::default().fg(Color::Green)),
                ]);

                ListItem::new(content)
            })
            .collect()
    };

    let title = if state.group.is_some() {
        " Group Members "
    } else {
        " Available Devices "
    };

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut list_state = ListState::default();
    if state.group.is_some() {
        if let Some(ref group) = state.group {
            if !group.members.is_empty() {
                list_state.select(Some(state.group_member_index));
            }
        }
    } else if !state.devices.is_empty() {
        list_state.select(Some(state.device_index));
    }

    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_group_actions(frame: &mut Frame, area: Rect, state: &AppState) {
    let actions = if state.group.is_some() {
        vec![
            Line::from(vec![
                Span::styled("[a]", Style::default().fg(Color::Yellow)),
                Span::raw(" Add device  "),
                Span::styled("[d]", Style::default().fg(Color::Yellow)),
                Span::raw(" Remove selected  "),
                Span::styled("[+/-]", Style::default().fg(Color::Yellow)),
                Span::raw(" Adjust volume"),
            ]),
            Line::from(vec![
                Span::styled("[x]", Style::default().fg(Color::Red)),
                Span::raw(" Disband group"),
            ]),
        ]
    } else {
        vec![Line::from(vec![
            Span::styled("[Enter]", Style::default().fg(Color::Yellow)),
            Span::raw(" Select devices  "),
            Span::styled("[g]", Style::default().fg(Color::Yellow)),
            Span::raw(" Create group from selection"),
        ])]
    };

    let para = Paragraph::new(actions)
        .block(Block::default().borders(Borders::ALL).title(" Actions "));

    frame.render_widget(para, area);
}
