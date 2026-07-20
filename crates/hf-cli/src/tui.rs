//! TUI for `oxfuzz` using ratatui.
//!
//! A focused target-inventory browser. Long-running fuzz execution stays in the
//! streaming CLI/GUI surfaces; this view provides accurate next commands.
//! Keybindings: q=quit, d=rediscover, r=show run command for selected target.

use std::io::{self, Stdout};
use std::path::{Path, PathBuf};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use hf_service::{ServiceContainer, TargetInventory, TargetLanguage};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;

/// The TUI application state.
pub struct Tui {
    /// Discovery goes through the service so results persist and business logic
    /// stays out of this presentation layer (AGENTS.md 2.9).
    container: ServiceContainer,
    project: PathBuf,
    lang: TargetLanguage,
    inventory: TargetInventory,
    selected: usize,
    log: Vec<String>,
    list_state: ListState,
}

impl Tui {
    /// Run the TUI for a project.
    ///
    /// # Errors
    /// Returns an error if the terminal cannot be initialized or an event
    /// loop error occurs.
    pub async fn run(project: &Path) -> anyhow::Result<()> {
        let lang = TargetLanguage::C;
        // Route discovery through the service container so results are persisted
        // (the DB) and ranked, instead of calling hf-discovery directly.
        let container = ServiceContainer::bootstrap().await;
        let inventory = container.discover(project, lang).await?;

        let mut app = Self {
            container,
            project: project.to_path_buf(),
            lang,
            inventory,
            selected: 0,
            log: vec![
                "Target browser ready. Press 'd' to re-discover, 'r' for the selected run command, or 'q' to quit."
                    .to_owned(),
            ],
            list_state: ListState::default(),
        };
        app.list_state
            .select((!app.inventory.candidates.is_empty()).then_some(0));

        let mut terminal = setup_terminal()?;
        // Run the event loop as an expression that yields its result, then ALWAYS
        // restore the terminal -- even on an I/O error from draw/poll/read -- so a
        // failure never leaves the user's shell stuck in raw/alternate-screen mode.
        let loop_result: std::io::Result<()> = loop {
            if let Err(e) = terminal.draw(|f| app.render(f)) {
                break Err(e);
            }
            let ready = match event::poll(std::time::Duration::from_millis(100)) {
                Ok(ready) => ready,
                Err(e) => break Err(e),
            };
            if ready {
                let ev = match event::read() {
                    Ok(ev) => ev,
                    Err(e) => break Err(e),
                };
                if let Event::Key(key) = ev {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') => break Ok(()),
                        KeyCode::Char('d') => {
                            app.log.push("Discovering...".to_owned());
                            match app.container.discover(&app.project, app.lang).await {
                                Ok(inv) => {
                                    app.inventory = inv;
                                    app.selected = app
                                        .selected
                                        .min(app.inventory.candidates.len().saturating_sub(1));
                                    app.list_state.select(
                                        (!app.inventory.candidates.is_empty())
                                            .then_some(app.selected),
                                    );
                                    app.log.push("Discovery complete.".to_owned());
                                }
                                Err(e) => app.log.push(format!("Discovery failed: {e}")),
                            }
                        }
                        KeyCode::Char('r') => {
                            if let Some(c) = app.inventory.ranked().get(app.selected) {
                                app.log.push(run_guidance(&app.project, &c.symbol));
                            }
                        }
                        KeyCode::Down if !app.inventory.candidates.is_empty() => {
                            app.selected =
                                (app.selected + 1).min(app.inventory.candidates.len() - 1);
                            app.list_state.select(Some(app.selected));
                        }
                        KeyCode::Up if app.selected > 0 => {
                            app.selected -= 1;
                            app.list_state.select(Some(app.selected));
                        }
                        _ => {}
                    }
                }
            }
        };
        // Restore the terminal unconditionally, then surface any loop error.
        let restore_result = restore_terminal(terminal);
        loop_result?;
        restore_result?;
        Ok(())
    }

    fn render(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(f.area());

        // Panel 0: Target inventory.
        let items: Vec<ListItem> = self
            .inventory
            .ranked()
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let style = if i == self.selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:.2} ", c.fit_score),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(&c.symbol, style),
                ]))
            })
            .collect();
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Discovered targets"),
            )
            .highlight_style(Style::default().bg(Color::DarkGray));
        f.render_stateful_widget(list, chunks[0], &mut self.list_state);

        // Panel 1: selected target facts and accurate next-step guidance.
        let mut details = Vec::new();
        if let Some(candidate) = self.inventory.ranked().get(self.selected) {
            details.extend([
                Line::from(vec![
                    Span::styled("Target: ", Style::default().fg(Color::Cyan)),
                    Span::raw(candidate.symbol.clone()),
                ]),
                Line::from(format!("Kind: {:?}", candidate.kind)),
                Line::from(format!(
                    "Location: {}:{}",
                    candidate.location.file.display(),
                    candidate.location.line
                )),
                Line::from(format!("Input surface: {:?}", candidate.input_surface)),
                Line::from(format!("Complexity: {}", candidate.complexity)),
                Line::from(format!(
                    "Reachable functions: {}",
                    candidate.reachable_functions.len()
                )),
                Line::from(""),
                Line::from("Guidance:"),
            ]);
        }
        details.extend(
            self.log
                .iter()
                .rev()
                .take(20)
                .map(|message| Line::from(message.as_str())),
        );
        let log = Paragraph::new(details).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Target details and next steps"),
        );
        f.render_widget(log, chunks[1]);
    }
}

fn run_guidance(project: &Path, symbol: &str) -> String {
    format!(
        "Run an already promoted harness with: oxfuzz run {} --target {symbol} --engine libfuzzer",
        project.display()
    )
}

type TerminalType = Terminal<CrosstermBackend<Stdout>>;

fn setup_terminal() -> io::Result<TerminalType> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn restore_terminal(mut terminal: TerminalType) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_guidance;
    use std::path::Path;

    #[test]
    fn target_browser_guidance_does_not_invent_a_provider_requirement() {
        let guidance = run_guidance(Path::new("/tmp/project"), "parse_packet");
        assert!(guidance.contains("oxfuzz run"));
        assert!(guidance.contains("parse_packet"));
        assert!(!guidance.to_ascii_lowercase().contains("provider"));
    }
}
