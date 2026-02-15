//! SSH transport implementation using russh.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use log::warn;
use russh::Channel;
use russh::client::{self, Handle, Msg};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey, load_secret_key};

use super::config::{AuthMethod, HostKeyVerification, SshConfig};
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

        let host_key_error: Arc<Mutex<Option<TransportError>>> = Arc::new(Mutex::new(None));

        let handler = SshHandler {
            host: config.host.clone(),
            port: config.port,
            host_key_verification: config.host_key_verification.clone(),
            known_hosts_path: config.known_hosts_path.clone(),
            host_key_error: host_key_error.clone(),
        };

        // Connect to the server
        let mut session = tokio::time::timeout(
            config.timeout,
            client::connect(ssh_config, (config.host.as_str(), config.port), handler),
        )
        .await
        .map_err(|_| TransportError::Timeout(config.timeout))?
        .map_err(|e| {
            // If check_server_key stored a detailed error, use that instead
            // of the generic russh::Error::UnknownKey
            if let Some(hk_err) = host_key_error.lock().unwrap().take() {
                hk_err
            } else {
                TransportError::Ssh(e)
            }
        })?;

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
    host: String,
    port: u16,
    host_key_verification: HostKeyVerification,
    known_hosts_path: Option<PathBuf>,
    /// Stores a detailed host-key error so connect() can surface it
    /// instead of the generic russh::Error::UnknownKey.
    host_key_error: Arc<Mutex<Option<TransportError>>>,
}

impl SshHandler {
    /// Check the host key against known_hosts.
    ///
    /// Returns `Ok(true)` if matched, `Ok(false)` if host not found,
    /// `Err(TransportError::HostKeyChanged)` if key changed.
    fn check_known_hosts(
        &self,
        pubkey: &PublicKey,
    ) -> std::result::Result<bool, TransportError> {
        let result = if let Some(ref path) = self.known_hosts_path {
            russh::keys::check_known_hosts_path(&self.host, self.port, pubkey, path)
        } else {
            russh::keys::check_known_hosts(&self.host, self.port, pubkey)
        };

        match result {
            Ok(matched) => Ok(matched),
            Err(russh::keys::Error::KeyChanged { line }) => {
                Err(TransportError::HostKeyChanged {
                    host: self.host.clone(),
                    port: self.port,
                    line,
                })
            }
            Err(e) => Err(TransportError::KnownHosts(e.to_string())),
        }
    }

    /// Save a new host key to known_hosts.
    fn learn_host_key(&self, pubkey: &PublicKey) -> std::result::Result<(), TransportError> {
        let result = if let Some(ref path) = self.known_hosts_path {
            russh::keys::known_hosts::learn_known_hosts_path(
                &self.host, self.port, pubkey, path,
            )
        } else {
            russh::keys::known_hosts::learn_known_hosts(&self.host, self.port, pubkey)
        };

        result.map_err(|e| TransportError::KnownHosts(e.to_string()))
    }
}

// TODO: Impl drop and warn if user is dropping without calling close

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        match self.host_key_verification {
            HostKeyVerification::Disabled => Ok(true),

            HostKeyVerification::AcceptNew => {
                match self.check_known_hosts(server_public_key) {
                    Ok(true) => Ok(true),
                    Ok(false) => {
                        // Unknown host — learn the key
                        if let Err(e) = self.learn_host_key(server_public_key) {
                            warn!("Failed to save host key: {}", e);
                        }
                        Ok(true)
                    }
                    Err(e) => {
                        // Key changed — store detailed error and reject
                        *self.host_key_error.lock().unwrap() = Some(e);
                        Ok(false)
                    }
                }
            }

            HostKeyVerification::Strict => {
                match self.check_known_hosts(server_public_key) {
                    Ok(true) => Ok(true),
                    Ok(false) => {
                        // Unknown host — reject in strict mode
                        *self.host_key_error.lock().unwrap() = Some(
                            TransportError::HostKeyUnknown {
                                host: self.host.clone(),
                                port: self.port,
                            },
                        );
                        Ok(false)
                    }
                    Err(e) => {
                        // Key changed — store detailed error and reject
                        *self.host_key_error.lock().unwrap() = Some(e);
                        Ok(false)
                    }
                }
            }
        }
    }
}
