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

// ── Состояние подключения ────────────────────────────────
#[derive(Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected { assigned_ip: String, started_at: Instant },
    Error(String),
}

// ── Экран ────────────────────────────────────────────────
#[derive(Clone, PartialEq)]
enum Screen {
    Main,
    Settings,
}

// ── Поле ввода ───────────────────────────────────────────
#[derive(Clone, PartialEq)]
enum InputField {
    ServerUrl,
    ServerKey,
}

// ── Общее состояние приложения ───────────────────────────
pub struct AppState {
    pub connection: ConnectionState,
    pub logs:       Vec<String>,
    pub server_url: String,
    pub server_key: String,
}

impl AppState {
    pub fn new(server_url: String, server_key: String) -> Self {
        Self {
            connection: ConnectionState::Disconnected,
            logs: Vec::new(),
            server_url,
            server_key,
        }
    }

    pub fn add_log(&mut self, msg: &str) {
        let now = chrono::Local::now().format("%H:%M:%S").to_string();
        self.logs.push(format!("[{}] {}", now, msg));
        if self.logs.len() > 200 {
            self.logs.remove(0);
        }
    }
}

// ── Команды от TUI к туннелю ─────────────────────────────
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

    // Инициализируем поля из текущего состояния
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
                                    state.lock().unwrap().add_log("Подключаюсь...");
                                    let _ = cmd_tx.send(TunnelCommand::Connect {
                                        url: url, key: srv_key
                                    });
                                }
                            }
                        }

                        KeyCode::Char('d') | KeyCode::Char('D') => {
                            let conn = state.lock().unwrap().connection.clone();
                            if matches!(conn,
                                ConnectionState::Connected { .. } | ConnectionState::Connecting)
                            {
                                state.lock().unwrap().add_log("Отключаюсь...");
                                let _ = cmd_tx.send(TunnelCommand::Disconnect);
                            }
                        }

                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            // Обновляем поля из текущего состояния при входе в настройки
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
    let area = f.size(); // ratatui 0.26 использует size()

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    // Заголовок
    let title = Paragraph::new("NOISE TUNNEL — КЛИЕНТ")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(title, chunks[0]);

    // Статус
    let (status_text, status_color) = match &state.connection {
        ConnectionState::Disconnected =>
            ("● ОТКЛЮЧЁН".to_string(), Color::Red),
        ConnectionState::Connecting =>
            ("◌ ПОДКЛЮЧЕНИЕ...".to_string(), Color::Yellow),
        ConnectionState::Connected { assigned_ip, started_at } => {
            let e = started_at.elapsed();
            let h = e.as_secs() / 3600;
            let m = (e.as_secs() % 3600) / 60;
            let s = e.as_secs() % 60;
            (format!("● ПОДКЛЮЧЁН  |  IP: {}  |  Аптайм: {:02}:{:02}:{:02}",
                assigned_ip, h, m, s), Color::Green)
        }
        ConnectionState::Error(e) =>
            (format!("✗ ОШИБКА: {}", e), Color::Red),
    };

    let status_body = format!("{}\nСервер: {}", status_text, state.server_url);
    let status = Paragraph::new(status_body)
        .block(Block::default().title(" Статус ").borders(Borders::ALL))
        .style(Style::default().fg(status_color));
    f.render_widget(status, chunks[1]);

    // Логи
    let log_items: Vec<ListItem> = state.logs.iter().rev().take(100)
        .map(|l| {
            let color = if l.contains('✓') || l.contains('♥') {
                Color::Green
            } else if l.contains('✗') || l.contains("ошибка") || l.contains("Ошибка") {
                Color::Red
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

    // Подсказки
    let hints = match &state.connection {
        ConnectionState::Disconnected | ConnectionState::Error(_) =>
            " [C] Подключить   [S] Настройки   [Q] Выход ",
        ConnectionState::Connecting =>
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

    // URL поле
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

    // KEY поле
    let key_display = if key_input.is_empty() {
        String::new()
    } else if *active_field == InputField::ServerKey {
        key_input.to_string()
    } else {
        // Показываем начало и конец ключа
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
