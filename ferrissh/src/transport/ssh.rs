//! SSH transport implementation using russh.

use std::sync::Arc;

use russh::Channel;
use russh::client::{self, Handle, Msg};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey, load_secret_key};

use super::config::{AuthMethod, SshConfig};
use crate::error::{Result, TransportError};

/// SSH transport wrapping russh client.
pub struct SshTransport {
    /// The russh session handle.
    session: Handle<SshHandler>,

    /// Configuration used for this connection.
    config: SshConfig,
}

impl SshTransport {
    /// Connect to the SSH server and authenticate.
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
            client::connect(ssh_config, (config.host.as_str(), config.port), handler),
        )
        .await
        .map_err(|_| TransportError::Timeout(config.timeout))?
        .map_err(TransportError::Ssh)?;

        // Authenticate
        Self::authenticate(&mut session, &config).await?;

        Ok(Self { session, config })
    }

    /// Open a new PTY channel on this connection.
    pub async fn open_channel(&self) -> Result<Channel<Msg>> {
        let channel = self
            .session
            .channel_open_session()
            .await
            .map_err(TransportError::Ssh)?;

        // Request PTY
        channel
            .request_pty(
                true,
                "xterm",
                self.config.terminal_width,
                self.config.terminal_height,
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

        Ok(channel)
    }

    /// Authenticate with the server.
    async fn authenticate(session: &mut Handle<SshHandler>, config: &SshConfig) -> Result<()> {
        let success = match &config.auth {
            AuthMethod::None => session
                .authenticate_none(&config.username)
                .await
                .map_err(TransportError::Ssh)?
                .success(),
            // TODO: Lets automatically handle auth interactive with password here
            AuthMethod::Password(password) => session
                .authenticate_password(&config.username, password)
                .await
                .map_err(TransportError::Ssh)?
                .success(),
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
        };

        if !success {
            return Err(TransportError::AuthenticationFailed {
                user: config.username.clone(),
            }
            .into());
        }

        Ok(())
    }

    /// Close the connection.
    pub async fn close(self) -> Result<()> {
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

// TODO: Impl drop and warn if user is dropping without calling close

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
