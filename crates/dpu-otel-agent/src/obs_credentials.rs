/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Keeps the obs-gateway credentials on disk fresh.
//!
//! The credentials are a second set of certificates, separate from the NICo API
//! client certificate that `ClientCertRenewer` maintains. They are fetched with
//! `GetObsGatewayCredentials`, and the next fetch is scheduled from the
//! lifetime of the certificate that came back, so the agent needs no
//! assumption about what TTL the credential source issues.

use std::ops::Range;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig, ForgeTlsClient};
use eyre::WrapErr;
use rand::RngExt;
use tokio::io::AsyncWriteExt;

use crate::config::{MIN_FETCH_FLOOR_SECS, ObsGatewayConfig};

/// The next fetch is due this far through the certificate's lifetime, chosen
/// per fetch so a fleet of DPUs does not refetch together. It stays below the
/// two-thirds point where a cert-manager backed source rotates, so an
/// unrotated credential is rarely fetched again.
const RENEW_AT_LIFETIME_FRACTION: Range<f64> = 0.5..0.6;

/// How long to wait before retrying a failed fetch, matching the NICo API
/// certificate renewal.
const FAILURE_RETRY_SECS: Range<u64> = 60..300;

/// How long a fetch may spend connecting to nico-api and waiting for the
/// response. `ForgeTlsClient::retry_build` retries on its own, and the fetch
/// shares a loop with the NICo API certificate renewal, so it must not block
/// that loop indefinitely. A timeout is handled as any other failed fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// How far the DPU's clock may be behind a certificate's `not_before` and the
/// certificate still be accepted, so a certificate issued moments ago is not
/// rejected over ordinary clock skew.
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;

pub(crate) struct ObsCredentialsRenewer {
    config: ObsGatewayConfig,
    forge_api_server: String,
    client_config: Arc<ForgeClientConfig>,
    next_fetch: Instant,
}

impl ObsCredentialsRenewer {
    /// The first fetch is due immediately: unlike the NICo API certificate,
    /// nothing else provisions these credentials.
    pub(crate) fn new(
        config: ObsGatewayConfig,
        forge_api_server: String,
        client_config: Arc<ForgeClientConfig>,
    ) -> Self {
        Self {
            config,
            forge_api_server,
            client_config,
            next_fetch: Instant::now(),
        }
    }

    pub(crate) async fn fetch_if_necessary(&mut self) {
        let now = Instant::now();
        if now < self.next_fetch {
            return;
        }
        let wait = match self.fetch().await {
            Ok(wait) => {
                tracing::info!(
                    next_fetch_in = %humantime::format_duration(wait),
                    "Fetched obs-gateway credentials"
                );
                wait
            }
            Err(err) => {
                let wait = Duration::from_secs(rand::rng().random_range(FAILURE_RETRY_SECS));
                tracing::warn!(
                    error = format!("{err:#}"),
                    retry_in = %humantime::format_duration(wait),
                    "Failed to fetch obs-gateway credentials"
                );
                wait
            }
        };
        self.next_fetch = now + wait;
    }

    /// Fetches and stores the credentials, returning how long to wait before
    /// the next fetch.
    async fn fetch(&self) -> eyre::Result<Duration> {
        let (csr_pem, local_key) = if self.config.use_csr {
            let (csr_pem, key_pem) = new_csr().wrap_err("failed to generate a CSR")?;
            (Some(csr_pem), Some(key_pem))
        } else {
            (None, None)
        };

        // Only the network calls are bounded: cancelling mid-write could leave
        // the credential files half replaced.
        let response = tokio::time::timeout(FETCH_TIMEOUT, async {
            let mut client = ForgeTlsClient::retry_build(&ApiConfig::new(
                &self.forge_api_server,
                &self.client_config,
            ))
            .await
            .wrap_err("failed to build forge API server client")?;

            let response = client
                .get_obs_gateway_credentials(tonic::Request::new(
                    rpc::GetObsGatewayCredentialsRequest { csr_pem },
                ))
                .await
                .wrap_err("error while executing the GetObsGatewayCredentials gRPC call")?
                .into_inner();
            eyre::Ok(response)
        })
        .await
        .wrap_err_with(|| {
            format!(
                "timed out after {} fetching obs-gateway credentials",
                humantime::format_duration(FETCH_TIMEOUT)
            )
        })??;

        let fraction = rand::rng().random_range(RENEW_AT_LIFETIME_FRACTION);
        store_credentials(&self.config, response, local_key, unix_now()?, fraction).await
    }
}

fn unix_now() -> eyre::Result<i64> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("the system clock is set before 1970")?;
    Ok(since_epoch.as_secs() as i64)
}

/// A fresh key pair and a PEM PKCS#10 request for its public key. The server
/// ignores everything in the request except the key and the proof of
/// possession, so the subject is left empty.
fn new_csr() -> eyre::Result<(String, String)> {
    let key = rcgen::KeyPair::generate()?;
    let csr = rcgen::CertificateParams::new(Vec::new())?.serialize_request(&key)?;
    Ok((csr.pem()?, key.serialize_pem()))
}

/// Writes the received credentials and returns how long to wait before the
/// next fetch. Nothing is written when the certificate is unusable.
async fn store_credentials(
    config: &ObsGatewayConfig,
    response: rpc::GetObsGatewayCredentialsResponse,
    local_key: Option<String>,
    now: i64,
    fraction: f64,
) -> eyre::Result<Duration> {
    let validity = leaf_validity(&response.client_cert_pem)?;
    let wait = next_fetch_delay(
        validity,
        now,
        fraction,
        config.min_fetch(),
        config.max_fetch(),
    )?;
    let key_pem = select_key(response.client_key_pem, local_key)?;

    // Stage every file before replacing any, so a failure to write one (a full
    // disk, an I/O error) cannot leave a new key beside an old certificate.
    let files = [
        (&config.ca_path, response.ca_pem.as_bytes(), 0o644),
        (&config.client_key_path, key_pem.as_bytes(), 0o600),
        (
            &config.client_cert_path,
            response.client_cert_pem.as_bytes(),
            0o644,
        ),
    ];
    let mut staged = Vec::new();
    for (path, contents, mode) in files {
        match stage(path, contents, mode).await {
            Ok(Some(file)) => staged.push(file),
            Ok(None) => {}
            Err(err) => {
                discard(staged).await;
                return Err(err);
            }
        }
    }
    commit(staged).await?;
    Ok(wait)
}

/// The key to pair with the received certificate. A key from the server wins
/// even when a CSR was sent: a source of shared static credentials cannot sign
/// a CSR, so the certificate it returns is for its own key.
fn select_key(server_key: Option<String>, local_key: Option<String>) -> eyre::Result<String> {
    server_key
        .filter(|key| !key.is_empty())
        .or(local_key)
        .ok_or_else(|| eyre::eyre!("nico-api returned no private key and no CSR was sent"))
}

/// A certificate's validity period, in seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Validity {
    not_before: i64,
    not_after: i64,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum ValidityError {
    #[error("the certificate's validity period is empty")]
    Empty,
    #[error("the certificate has already expired")]
    Expired,
    #[error("the certificate is not valid yet, so the system clock is likely behind")]
    NotYetValid,
}

/// The validity of the first certificate in `cert_pem`, the leaf by
/// convention. Read from the certificate itself, not from the response, so
/// the schedule follows the certificate that is actually written.
fn leaf_validity(cert_pem: &str) -> eyre::Result<Validity> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .wrap_err("client_cert_pem is not valid PEM")?;
    let cert = pem
        .parse_x509()
        .wrap_err("client_cert_pem does not start with a valid certificate")?;
    let validity = cert.validity();
    Ok(Validity {
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
    })
}

/// How long to wait before the next fetch: until `fraction` of the way through
/// the lifetime, so a certificate fetched late in its life is refetched
/// sooner. The wait is held between `min` and `max`, raised to the hard floor
/// that keeps an unrotated credential from being polled tightly, and finally
/// capped at half the remaining lifetime, which takes precedence over the
/// floor so a short-lived certificate is refetched before it expires. A
/// certificate that is not valid yet is refused, since the schedule would be
/// computed from a clock that is behind and could outlast the certificate.
fn next_fetch_delay(
    validity: Validity,
    now: i64,
    fraction: f64,
    min: Duration,
    max: Duration,
) -> Result<Duration, ValidityError> {
    let lifetime = validity.not_after - validity.not_before;
    if lifetime <= 0 {
        return Err(ValidityError::Empty);
    }
    if now >= validity.not_after {
        return Err(ValidityError::Expired);
    }
    if now + CLOCK_SKEW_TOLERANCE_SECS < validity.not_before {
        return Err(ValidityError::NotYetValid);
    }

    let renew_at = validity.not_before as f64 + lifetime as f64 * fraction;
    let remaining = Duration::from_secs((validity.not_after - now) as u64);
    Ok(Duration::from_secs_f64((renew_at - now as f64).max(0.0))
        .clamp(min, max)
        .max(Duration::from_secs(MIN_FETCH_FLOOR_SECS))
        .min(remaining / 2))
}

/// A file written beside its destination, waiting to be renamed into place.
struct Staged {
    tmp_path: PathBuf,
    path: PathBuf,
}

/// Writes `contents` to a temp file beside `path`, created with `mode` from its
/// first byte and synced. Returns `None` when `path` already holds `contents`,
/// so refetching an unrotated credential does not touch it. The temp file is
/// removed if writing it fails.
async fn stage(path: &Path, contents: &[u8], mode: u32) -> eyre::Result<Option<Staged>> {
    if tokio::fs::read(path)
        .await
        .is_ok_and(|existing| existing == contents)
    {
        return Ok(None);
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }

    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);

    // A temp file left by an earlier crash keeps whatever mode it was created
    // with, so remove it and let `create_new` apply `mode` to a fresh file.
    match tokio::fs::remove_file(&tmp_path).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).wrap_err_with(|| format!("failed to remove {}", tmp_path.display()));
        }
    }

    let write = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp_path)
            .await?;
        // The umask can clear bits from `mode` at creation.
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .await?;
        file.write_all(contents).await?;
        file.sync_all().await
    };
    if let Err(err) = write.await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(err).wrap_err_with(|| format!("failed to write {}", path.display()));
    }
    Ok(Some(Staged {
        tmp_path,
        path: path.to_path_buf(),
    }))
}

async fn discard(staged: Vec<Staged>) {
    for file in staged {
        let _ = tokio::fs::remove_file(&file.tmp_path).await;
    }
}

/// Renames each staged file into place, so a reader never sees a partial file.
/// Only a crash or a failed rename between two renames can leave the files
/// mismatched, and the agent fetches again on start.
async fn commit(staged: Vec<Staged>) -> eyre::Result<()> {
    let mut staged = staged.into_iter();
    while let Some(file) = staged.next() {
        if let Err(err) = tokio::fs::rename(&file.tmp_path, &file.path).await {
            let _ = tokio::fs::remove_file(&file.tmp_path).await;
            discard(staged.collect()).await;
            return Err(err).wrap_err_with(|| format!("failed to write {}", file.path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;
    use x509_parser::prelude::FromDer;

    use super::*;

    const DAY: i64 = 24 * 60 * 60;
    const MIN: Duration = Duration::from_secs(300);
    const MAX: Duration = Duration::from_secs(7 * DAY as u64);

    /// Each row is `(lifetime, seconds into the lifetime, fraction)` for a
    /// certificate that starts at the epoch.
    #[test]
    fn next_fetch_delay_follows_the_certificate_lifetime() {
        let delay = |(lifetime, age, fraction): (i64, i64, f64)| {
            let validity = Validity {
                not_before: 0,
                not_after: lifetime,
            };
            next_fetch_delay(validity, age, fraction, MIN, MAX)
        };
        scenarios!(
            run = delay;
            "a long lifetime is capped at the maximum" {
                (365 * DAY, 0, 0.5) => Yields(MAX),
            }

            "a medium lifetime is renewed partway through" {
                (10 * DAY, 0, 0.5) => Yields(Duration::from_secs(5 * DAY as u64)),
                (10 * DAY, 0, 0.6) => Yields(Duration::from_secs(5 * DAY as u64)),
            }

            "a certificate fetched late is renewed sooner" {
                (10 * DAY, 6 * DAY, 0.5) => Yields(MIN),
            }

            "the floor does not push a short-lived certificate past expiry" {
                (100, 0, 0.5) => Yields(Duration::from_secs(50)),
            }

            "a clock slightly behind the issuer is tolerated" {
                (10 * DAY, -30, 0.5) => Yields(Duration::from_secs(5 * DAY as u64 + 15)),
            }

            "an unusable certificate" {
                (10 * DAY, -61, 0.5) => FailsWith(ValidityError::NotYetValid),
                (10 * DAY, 10 * DAY, 0.5) => FailsWith(ValidityError::Expired),
                (10 * DAY, 11 * DAY, 0.5) => FailsWith(ValidityError::Expired),
                (0, 0, 0.5) => FailsWith(ValidityError::Empty),
            }
        );
    }

    #[test]
    fn select_key_prefers_the_server_key() {
        let key = |s: &str| Some(s.to_string());
        scenarios!(
            run = |(server, local): (Option<String>, Option<String>)| select_key(server, local)
                .map_err(drop);
            "a CSR was honored" {
                (None, key("local")) => Yields("local".to_string()),
            }

            "the source returned its own key" {
                (key("server"), key("local")) => Yields("server".to_string()),
                (key("server"), None) => Yields("server".to_string()),
                (key(""), key("local")) => Yields("local".to_string()),
            }

            "no key to pair with the certificate" {
                (None, None) => Fails,
            }
        );
    }

    fn cert_pem(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["dpu.test".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.self_signed(&key).unwrap().pem()
    }

    fn config_in(dir: &Path) -> ObsGatewayConfig {
        ObsGatewayConfig {
            ca_path: dir.join("obs/ca.pem"),
            client_cert_path: dir.join("obs/cert.pem"),
            client_key_path: dir.join("obs/private/key.pem"),
            use_csr: true,
            min_fetch_secs: 300,
            max_fetch_secs: 7 * DAY as u64,
        }
    }

    fn response(cert: &str, key: Option<&str>) -> rpc::GetObsGatewayCredentialsResponse {
        rpc::GetObsGatewayCredentialsResponse {
            ca_pem: "ca".to_string(),
            client_cert_pem: cert.to_string(),
            client_key_pem: key.map(str::to_string),
            not_after: None,
        }
    }

    /// A CSR was honored: the files hold the local key, the key is private to
    /// the owner, and the schedule comes from the certificate.
    #[tokio::test]
    async fn stores_the_local_key_for_a_csr_issued_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let cert = cert_pem((2026, 1, 1), (2026, 1, 11));
        let validity = leaf_validity(&cert).unwrap();

        let wait = store_credentials(
            &config,
            response(&cert, None),
            Some("local-key".to_string()),
            validity.not_before,
            0.5,
        )
        .await
        .unwrap();

        assert_eq!(wait, Duration::from_secs(5 * DAY as u64));
        assert_eq!(std::fs::read_to_string(&config.ca_path).unwrap(), "ca");
        assert_eq!(
            std::fs::read_to_string(&config.client_cert_path).unwrap(),
            cert
        );
        assert_eq!(
            std::fs::read_to_string(&config.client_key_path).unwrap(),
            "local-key"
        );
        let mode = std::fs::metadata(&config.client_key_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// An expired certificate is not installed over the working one.
    #[tokio::test]
    async fn an_expired_certificate_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let cert = cert_pem((2026, 1, 1), (2026, 1, 11));
        let validity = leaf_validity(&cert).unwrap();

        let result = store_credentials(
            &config,
            response(&cert, Some("server-key")),
            None,
            validity.not_after,
            0.5,
        )
        .await;

        assert!(result.is_err());
        assert!(!config.ca_path.exists());
        assert!(!config.client_key_path.exists());
    }

    /// A file that cannot be written leaves the others untouched, so the key
    /// is never replaced without its certificate.
    #[tokio::test]
    async fn a_failed_write_replaces_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config_in(dir.path());
        // A directory cannot be created under a regular file.
        std::fs::write(dir.path().join("blocker"), "").unwrap();
        config.client_cert_path = dir.path().join("blocker/cert.pem");
        let cert = cert_pem((2026, 1, 1), (2026, 1, 11));
        let validity = leaf_validity(&cert).unwrap();

        let result = store_credentials(
            &config,
            response(&cert, Some("server-key")),
            None,
            validity.not_before,
            0.5,
        )
        .await;

        assert!(result.is_err());
        assert!(!config.ca_path.exists());
        assert!(!config.client_key_path.exists());
        assert!(!config.ca_path.with_file_name("ca.pem.tmp").exists());
        assert!(
            !config
                .client_key_path
                .with_file_name("key.pem.tmp")
                .exists()
        );
    }

    /// A temp file left by a crash, created world-readable, does not carry its
    /// mode over to the private key.
    #[tokio::test]
    async fn a_stale_temp_file_does_not_weaken_the_key_mode() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let stale = config.client_key_path.with_file_name("key.pem.tmp");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, "old").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();
        let cert = cert_pem((2026, 1, 1), (2026, 1, 11));
        let validity = leaf_validity(&cert).unwrap();

        store_credentials(
            &config,
            response(&cert, Some("server-key")),
            None,
            validity.not_before,
            0.5,
        )
        .await
        .unwrap();

        let mode = std::fs::metadata(&config.client_key_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!stale.exists());
    }

    /// The generated request is a well-formed PKCS#10 CSR whose signature
    /// verifies, which is what the server checks before issuing.
    #[test]
    fn generated_csr_verifies() {
        let (csr_pem, key_pem) = new_csr().unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes()).unwrap();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
                .unwrap();
        csr.verify_signature().unwrap();
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }
}
