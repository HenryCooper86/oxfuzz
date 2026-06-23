//! TUI for `hobot_fuzz` using ratatui.
//!
//! Three panels: target inventory, run progress, crash list.
//! Keybindings: q=quit, Tab=next panel, d=discover, r=run selected.

use std::io::{self, Stdout};
use std::path::Path;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use hf_core::target::TargetInventory;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;

/// The TUI application state.
pub struct Tui {
    inventory: TargetInventory,
    selected: usize,
    active_panel: usize,
    log: Vec<String>,
    crashes: Vec<String>,
    list_state: ListState,
}

impl Tui {
    /// Run the TUI for a project.
    ///
    /// # Errors
    /// Returns an error if the terminal cannot be initialized or an event
    /// loop error occurs.
    pub async fn run(project: &Path) -> anyhow::Result<()> {
        let lang = hf_core::target::TargetLanguage::C;
        let inventory = hf_discovery::discover(project, lang).await?;

        let mut app = Self {
            inventory,
            selected: 0,
            active_panel: 0,
            log: vec!["Press 'd' to re-discover, 'r' to run, 'q' to quit.".to_owned()],
            crashes: Vec::new(),
            list_state: ListState::default(),
        };
        app.list_state.select(Some(0));

        let mut terminal = setup_terminal()?;
        loop {
            terminal.draw(|f| app.render(f))?;
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Tab => {
                            app.active_panel = (app.active_panel + 1) % 3;
                        }
                        KeyCode::Char('d') => {
                            app.log.push("Discovering...".to_owned());
                            if let Ok(inv) = hf_discovery::discover(project, lang).await {
                                app.inventory = inv;
                                app.log.push("Discovery complete.".to_owned());
                            }
                        }
                        KeyCode::Char('r') => {
                            if let Some(c) = app.inventory.ranked().get(app.selected) {
                                app.log.push(format!("Run: {}", c.symbol));
                                // In a real implementation this would start
                                // a fuzz run in the background and stream
                                // progress. For now, just log it.
                                app.log
                                    .push("  (run not started -- needs LLM + Docker)".to_owned());
                            }
                        }
                        KeyCode::Down
                            if app.active_panel == 0 && !app.inventory.candidates.is_empty() =>
                        {
                            app.selected =
                                (app.selected + 1).min(app.inventory.candidates.len() - 1);
                            app.list_state.select(Some(app.selected));
                        }
                        KeyCode::Up if app.active_panel == 0 && app.selected > 0 => {
                            app.selected -= 1;
                            app.list_state.select(Some(app.selected));
                        }
                        _ => {}
                    }
                }
            }
        }
        restore_terminal(terminal)?;
        Ok(())
    }

    fn render(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(40),
                Constraint::Percentage(40),
                Constraint::Percentage(20),
            ])
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
        let title = if self.active_panel == 0 {
            "Targets [*]"
        } else {
            "Targets"
        };
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().bg(Color::DarkGray));
        f.render_stateful_widget(list, chunks[0], &mut self.list_state);

        // Panel 1: Run log / progress.
        let log_items: Vec<Line> = self
            .log
            .iter()
            .rev()
            .take(30)
            .map(|s| Line::from(s.as_str()))
            .collect();
        let title = if self.active_panel == 1 {
            "Progress [*]"
        } else {
            "Progress"
        };
        let log =
            Paragraph::new(log_items).block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(log, chunks[1]);

        // Panel 2: Crashes.
        let crash_items: Vec<ListItem> = self
            .crashes
            .iter()
            .map(|s| ListItem::new(Line::from(s.as_str())))
            .collect();
        let title = if self.active_panel == 2 {
            "Crashes [*]"
        } else {
            "Crashes"
        };
        let crashes =
            List::new(crash_items).block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(crashes, chunks[2]);
    }
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
