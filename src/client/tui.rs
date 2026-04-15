use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::*,
};

const CONFIG_FILE: &str = "/tmp/vpn.config";

// ── Состояние подключения ────────────────────────────────
#[derive(Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Reconnecting { attempt: u32 },
    Connected { assigned_ip: String, started_at: Instant },
    Error(String),
}

#[derive(Clone, PartialEq)]
enum Screen {
    Main,
    Settings,
}

#[derive(Clone, PartialEq)]
enum InputField {
    ServerUrl,
    ServerKey,
}

// ── Конфиг (сохраняется на диск) ─────────────────────────
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Config {
    server_url: String,
    server_key: String,
}

impl Config {
    fn load() -> Self {
        std::fs::read_to_string(CONFIG_FILE)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            std::fs::write(CONFIG_FILE, json).ok();
        }
    }
}

// ── Статистика трафика ───────────────────────────────────
#[derive(Default, Clone)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl TrafficStats {
    pub fn rx_str(&self) -> String { format_bytes(self.rx_bytes) }
    pub fn tx_str(&self) -> String { format_bytes(self.tx_bytes) }
}

fn format_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else if b < 1024 * 1024 * 1024 {
        format!("{:.2} MB", b as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// ── Общее состояние приложения ───────────────────────────
pub struct AppState {
    pub connection: ConnectionState,
    pub logs:       Vec<String>,
    pub server_url: String,
    pub server_key: String,
    pub stats:      TrafficStats,
    pub auto_reconnect: bool,
}

impl AppState {
    pub fn new(server_url: String, server_key: String) -> Self {
        let cfg = Config::load();
        Self {
            connection: ConnectionState::Disconnected,
            logs: Vec::new(),
            server_url: if server_url.is_empty() { cfg.server_url } else { server_url },
            server_key: if server_key.is_empty() { cfg.server_key } else { server_key },
            stats: TrafficStats::default(),
            auto_reconnect: true,
        }
    }

    pub fn add_log(&mut self, msg: &str) {
        let now = chrono::Local::now().format("%H:%M:%S").to_string();
        self.logs.push(format!("[{}] {}", now, msg));
        if self.logs.len() > 200 {
            self.logs.remove(0);
        }
    }

    pub fn add_rx(&mut self, bytes: u64) {
        self.stats.rx_bytes += bytes;
    }

    pub fn add_tx(&mut self, bytes: u64) {
        self.stats.tx_bytes += bytes;
    }

    pub fn reset_stats(&mut self) {
        self.stats = TrafficStats::default();
    }

    pub fn save_config(&self) {
        Config {
            server_url: self.server_url.clone(),
            server_key: self.server_key.clone(),
        }.save();
    }
}

// ── Команды ──────────────────────────────────────────────
pub enum TunnelCommand {
    Connect { url: String, key: String },
    Disconnect,
}

// ── Запуск TUI ───────────────────────────────────────────
pub fn run_tui(
    state:  Arc<Mutex<AppState>>,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<TunnelCommand>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend      = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut screen       = Screen::Main;
    let mut active_field = InputField::ServerUrl;

    let (mut url_input, mut key_input) = {
        let s = state.lock().unwrap();
        (s.server_url.clone(), s.server_key.clone())
    };

    loop {
        terminal.draw(|f| {
            let s = state.lock().unwrap();
            match screen {
                Screen::Main     => draw_main(f, &s),
                Screen::Settings => draw_settings(f, &url_input, &key_input, &active_field),
            }
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }

                match screen {
                    Screen::Main => match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,

                        KeyCode::Char('c') | KeyCode::Char('C') => {
                            let (conn, url, srv_key) = {
                                let s = state.lock().unwrap();
                                (s.connection.clone(), s.server_url.clone(), s.server_key.clone())
                            };
                            if conn == ConnectionState::Disconnected
                                || matches!(conn, ConnectionState::Error(_))
                            {
                                if url.is_empty() || srv_key.is_empty() {
                                    state.lock().unwrap()
                                        .add_log("✗ Укажи URL и ключ в настройках (S)");
                                } else {
                                    let mut s = state.lock().unwrap();
                                    s.add_log("Подключаюсь...");
                                    s.reset_stats();
                                    drop(s);
                                    let _ = cmd_tx.send(TunnelCommand::Connect {
                                        url, key: srv_key
                                    });
                                }
                            }
                        }

                        KeyCode::Char('d') | KeyCode::Char('D') => {
                            let conn = state.lock().unwrap().connection.clone();
                            if matches!(conn,
                                ConnectionState::Connected { .. }
                                | ConnectionState::Connecting
                                | ConnectionState::Reconnecting { .. })
                            {
                                state.lock().unwrap().add_log("Отключаюсь...");
                                let _ = cmd_tx.send(TunnelCommand::Disconnect);
                            }
                        }

                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            let s = state.lock().unwrap();
                            url_input = s.server_url.clone();
                            key_input = s.server_key.clone();
                            drop(s);
                            screen = Screen::Settings;
                            active_field = InputField::ServerUrl;
                        }

                        _ => {}
                    },

                    Screen::Settings => match key.code {
                        KeyCode::Esc => {
                            screen = Screen::Main;
                        }

                        KeyCode::Tab => {
                            active_field = match active_field {
                                InputField::ServerUrl => InputField::ServerKey,
                                InputField::ServerKey => InputField::ServerUrl,
                            };
                        }

                        KeyCode::Enter => {
                            let mut s = state.lock().unwrap();
                            s.server_url = url_input.clone();
                            s.server_key = key_input.clone();
                            s.save_config();
                            s.add_log("✓ Настройки сохранены");
                            drop(s);
                            screen = Screen::Main;
                        }

                        KeyCode::Char(c) => {
                            match active_field {
                                InputField::ServerUrl => url_input.push(c),
                                InputField::ServerKey => key_input.push(c),
                            }
                        }

                        KeyCode::Backspace => {
                            match active_field {
                                InputField::ServerUrl => { url_input.pop(); }
                                InputField::ServerKey => { key_input.pop(); }
                            }
                        }

                        _ => {}
                    },
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

// ── Главный экран ────────────────────────────────────────
fn draw_main(f: &mut Frame, state: &AppState) {
    let area = f.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // заголовок
            Constraint::Length(6),  // статус + статистика
            Constraint::Min(5),     // логи
            Constraint::Length(3),  // подсказки
        ])
        .split(area);

    // ── Заголовок ────────────────────────────────────────
    let title = Paragraph::new("⚡ NOISE TUNNEL — КЛИЕНТ")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(title, chunks[0]);

    // ── Статус + трафик ──────────────────────────────────
    let status_area = chunks[1];
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(status_area);

    let (status_text, status_color) = match &state.connection {
        ConnectionState::Disconnected =>
            ("● ОТКЛЮЧЁН".to_string(), Color::Red),
        ConnectionState::Connecting =>
            ("◌ ПОДКЛЮЧЕНИЕ...".to_string(), Color::Yellow),
        ConnectionState::Reconnecting { attempt } =>
            (format!("↻ ПЕРЕПОДКЛЮЧЕНИЕ... (попытка {})", attempt), Color::Yellow),
        ConnectionState::Connected { assigned_ip, started_at } => {
            let e = started_at.elapsed();
            let h = e.as_secs() / 3600;
            let m = (e.as_secs() % 3600) / 60;
            let s = e.as_secs() % 60;
            (format!("● ПОДКЛЮЧЁН\nIP: {}\nАптайм: {:02}:{:02}:{:02}", assigned_ip, h, m, s),
             Color::Green)
        }
        ConnectionState::Error(e) =>
            (format!("✗ ОШИБКА:\n{}", e), Color::Red),
    };

    let status_body = format!("{}\nСервер: {}", status_text, state.server_url);
    let status = Paragraph::new(status_body)
        .block(Block::default().title(" Статус ").borders(Borders::ALL))
        .style(Style::default().fg(status_color));
    f.render_widget(status, status_chunks[0]);

    // ── Статистика трафика ───────────────────────────────
    let traffic_text = format!(
        "↓ RX: {}\n↑ TX: {}\n\nАвто-реконнект: {}",
        state.stats.rx_str(),
        state.stats.tx_str(),
        if state.auto_reconnect { "вкл" } else { "выкл" },
    );
    let traffic = Paragraph::new(traffic_text)
        .block(Block::default().title(" Трафик ").borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(traffic, status_chunks[1]);

    // ── Логи ─────────────────────────────────────────────
    let log_items: Vec<ListItem> = state.logs.iter().rev().take(100)
        .map(|l| {
            let color = if l.contains('✓') || l.contains('♥') {
                Color::Green
            } else if l.contains('✗') || l.contains("ошибка") || l.contains("Ошибка") {
                Color::Red
            } else if l.contains("↻") || l.contains("Переподкл") {
                Color::Yellow
            } else if l.contains("Подключ") || l.contains("handshake") {
                Color::Yellow
            } else {
                Color::Gray
            };
            ListItem::new(l.as_str()).style(Style::default().fg(color))
        })
        .collect();

    let logs = List::new(log_items)
        .block(Block::default()
            .title(" Логи (новые сверху) ")
            .borders(Borders::ALL));
    f.render_widget(logs, chunks[2]);

    // ── Подсказки ────────────────────────────────────────
    let hints = match &state.connection {
        ConnectionState::Disconnected | ConnectionState::Error(_) =>
            " [C] Подключить   [S] Настройки   [Q] Выход ",
        ConnectionState::Connecting | ConnectionState::Reconnecting { .. } =>
            " [D] Отменить   [Q] Выход ",
        ConnectionState::Connected { .. } =>
            " [D] Отключить   [S] Настройки   [Q] Выход ",
    };

    let hints_w = Paragraph::new(hints)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hints_w, chunks[3]);
}

// ── Экран настроек ───────────────────────────────────────
fn draw_settings(
    f:            &mut Frame,
    url_input:    &str,
    key_input:    &str,
    active_field: &InputField,
) {
    let area = f.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let title = Paragraph::new("НАСТРОЙКИ")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(title, chunks[0]);

    let url_border = if *active_field == InputField::ServerUrl {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Gray)
    };
    let url_w = Paragraph::new(url_input)
        .block(Block::default()
            .title(" URL сервера (wss://...) ")
            .borders(Borders::ALL)
            .border_style(url_border));
    f.render_widget(url_w, chunks[1]);

    let key_display = if key_input.is_empty() {
        String::new()
    } else if *active_field == InputField::ServerKey {
        key_input.to_string()
    } else {
        let start = &key_input[..8.min(key_input.len())];
        let end   = &key_input[key_input.len().saturating_sub(8)..];
        format!("{}...{}", start, end)
    };

    let key_border = if *active_field == InputField::ServerKey {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Gray)
    };
    let key_w = Paragraph::new(key_display)
        .block(Block::default()
            .title(" Публичный ключ сервера (hex) ")
            .borders(Borders::ALL)
            .border_style(key_border));
    f.render_widget(key_w, chunks[2]);

    let hints = Paragraph::new(
        " [Tab] Следующее поле   [Enter] Сохранить   [Esc] Назад "
    )
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL))
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hints, chunks[3]);
}
