//! Mock SSH server for integration tests.
//!
//! Uses `russh::server` to run an in-process SSH server that executes
//! commands via `bash -c`. No openssh-server or SSH keys required.
//!
//! The server runs on a dedicated thread with its own tokio runtime so
//! it outlives individual `#[tokio::test]` runtimes.

use std::sync::{Arc, OnceLock};

use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Session as ServerSession};
use russh::{Channel, ChannelId, CryptoVec};

const PROMPT: &str = "user@mock:~$ ";

static MOCK_PORT: OnceLock<u16> = OnceLock::new();

/// Returns the port of the running mock SSH server, starting it if needed.
pub async fn mock_server_port() -> u16 {
    *MOCK_PORT.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("failed to create runtime");
            rt.block_on(async {
                let port = start_server().await;
                tx.send(port).expect("failed to send port");
            });
            // Keep the runtime alive so the server keeps running.
            rt.block_on(std::future::pending::<()>());
        });
        rx.recv().expect("failed to receive port")
    })
}

async fn start_server() -> u16 {
    let key = PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::OsRng,
        Algorithm::Ed25519,
    )
    .expect("failed to generate server key");

    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        ..Default::default()
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let config = config.clone();
            tokio::spawn(async move {
                let handler = ShellHandler::new();
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });

    port
}

struct ShellHandler {
    buf: Vec<u8>,
}

impl ShellHandler {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
}

impl server::Handler for ShellHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(&mut self, _: &str, _: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.data(channel, CryptoVec::from(PROMPT.as_bytes().to_vec()))?;
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.buf.extend_from_slice(data);

        while let Some(nl_pos) = self.buf.iter().position(|&b| b == b'\n') {
            let command: String = String::from_utf8_lossy(&self.buf[..nl_pos])
                .trim()
                .to_string();
            self.buf.drain(..=nl_pos);

            // Echo the command (simulates PTY echo)
            session.data(
                channel,
                CryptoVec::from(format!("{}\n", command).into_bytes()),
            )?;

            // Execute the command
            if !command.is_empty() {
                if let Ok(output) = tokio::process::Command::new("bash")
                    .arg("-c")
                    .arg(&command)
                    .output()
                    .await
                {
                    if !output.stdout.is_empty() {
                        session.data(channel, CryptoVec::from(output.stdout))?;
                    }
                }
            }

            // Send prompt
            session.data(channel, CryptoVec::from(PROMPT.as_bytes().to_vec()))?;
        }

        Ok(())
    }
}
