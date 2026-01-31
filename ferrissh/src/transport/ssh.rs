//! SSH transport implementation using russh.

use std::sync::Arc;
use std::time::Duration;

use regex::bytes::Regex;
use russh::client::{self, Handle, Msg};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKey};
use russh::Channel;

use super::config::{AuthMethod, SshConfig};
use crate::channel::PatternBuffer;
use crate::error::{Result, TransportError};

/// SSH transport wrapping russh client.
pub struct SshTransport {
    /// The russh session handle.
    session: Handle<SshHandler>,

    /// The PTY channel for interactive session.
    channel: Channel<Msg>,

    /// Buffer for accumulating and searching output.
    buffer: PatternBuffer,

    /// Configuration used for this connection.
    config: SshConfig,
}

impl SshTransport {
    /// Connect to the SSH server.
    pub async fn connect(config: SshConfig) -> Result<Self> {
        let ssh_config = Arc::new(client::Config {
            inactivity_timeout: Some(config.timeout),
            ..Default::default()
        });

        let handler = SshHandler {
            verify_host_key: config.verify_host_key,
        };

        // Connect to the server
        let mut session = tokio::time::timeout(
            config.timeout,
            client::connect(ssh_config, config.socket_addr(), handler),
        )
        .await
        .map_err(|_| TransportError::Timeout(config.timeout))?
        .map_err(TransportError::Ssh)?;

        // Authenticate
        Self::authenticate(&mut session, &config).await?;

        // Open PTY channel
        let channel = session
            .channel_open_session()
            .await
            .map_err(TransportError::Ssh)?;

        // Request PTY
        channel
            .request_pty(
                false,
                "xterm",
                config.terminal_width,
                config.terminal_height,
                0,
                0,
                &[],
            )
            .await
            .map_err(TransportError::Ssh)?;

        // Request shell
        channel
            .request_shell(true)
            .await
            .map_err(TransportError::Ssh)?;

        Ok(Self {
            session,
            channel,
            buffer: PatternBuffer::new(1000),
            config,
        })
    }

    /// Authenticate with the server.
    async fn authenticate(session: &mut Handle<SshHandler>, config: &SshConfig) -> Result<()> {
        let success = match &config.auth {
            AuthMethod::None => {
                session
                    .authenticate_none(&config.username)
                    .await
                    .map_err(TransportError::Ssh)?
                    .success()
            }
            AuthMethod::Password(password) => {
                session
                    .authenticate_password(&config.username, password)
                    .await
                    .map_err(TransportError::Ssh)?
                    .success()
            }
            AuthMethod::PrivateKey { path, passphrase } => {
                let key = load_secret_key(path, passphrase.as_deref())
                    .map_err(|e| TransportError::Key(e.to_string()))?;

                // Get the best RSA hash algorithm supported by the server
                let hash_alg = session
                    .best_supported_rsa_hash()
                    .await
                    .map_err(TransportError::Ssh)?
                    .flatten();

                session
                    .authenticate_publickey(
                        &config.username,
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
                    )
                    .await
                    .map_err(TransportError::Ssh)?
                    .success()
            }
            AuthMethod::Agent => {
                // TODO: Implement SSH agent support
                return Err(TransportError::AuthenticationFailed {
                    user: config.username.clone(),
                }
                .into());
            }
        };

        if !success {
            return Err(TransportError::AuthenticationFailed {
                user: config.username.clone(),
            }
            .into());
        }

        Ok(())
    }

    /// Send data to the channel.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.channel
            .data(data)
            .await
            .map_err(TransportError::Ssh)?;
        Ok(())
    }

    /// Send a command (with newline).
    pub async fn send(&mut self, command: &str) -> Result<()> {
        let data = format!("{}\n", command);
        self.write(data.as_bytes()).await
    }

    /// Read until pattern matches (with timeout).
    pub async fn read_until_pattern(
        &mut self,
        pattern: &Regex,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        use russh::ChannelMsg;

        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(TransportError::Timeout(timeout).into());
                }
                msg = self.channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            self.buffer.extend(&data);
                            if self.buffer.search_tail(pattern).is_some() {
                                return Ok(self.buffer.take());
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                            // stderr - also add to buffer
                            self.buffer.extend(&data);
                        }
                        Some(ChannelMsg::Eof) | None => {
                            return Err(TransportError::Disconnected.into());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Get current buffer contents without clearing.
    pub fn peek_buffer(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    /// Clear the buffer.
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
    }

    /// Close the connection.
    pub async fn close(self) -> Result<()> {
        drop(self.channel);
        self.session
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .map_err(TransportError::Ssh)?;
        Ok(())
    }
}

/// SSH client handler for russh.
struct SshHandler {
    verify_host_key: bool,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // TODO: Implement proper known_hosts checking
        if self.verify_host_key {
            // For now, always accept when verification is enabled
            // Real implementation should check against known_hosts
            Ok(true)
        } else {
            Ok(true)
        }
    }
}
