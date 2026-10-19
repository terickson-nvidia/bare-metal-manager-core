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

//! Configuration of the DPU otel-agent.
//!
//! This is deliberately its own schema and not `AgentConfig`, which belongs to
//! forge-dpu-agent. The agent still reads the `[forge-system]` and
//! `[period] main-loop-idle-secs` keys of deployed `config.toml` files, and
//! ignores every other key those files carry, so they keep working.

use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_tls::default as tls_default;
use serde::Deserialize;

const DEFAULT_API_SERVER: &str = "https://carbide-api.forge";

/// Hard lower bound on `min-fetch-secs`: below it a rotation that has not
/// happened yet would turn into a tight polling loop against nico-api.
pub(crate) const MIN_FETCH_FLOOR_SECS: u64 = 60;

/// Hard upper bound on `max-fetch-secs`: above it a changed CA bundle or
/// credential source would take over a month to reach the DPU.
const MAX_FETCH_CEILING_SECS: u64 = 30 * 24 * 60 * 60;

/// Unknown keys are ignored here, and in `ForgeSystemConfig` and
/// `PeriodConfig`, on purpose: deployed forge-dpu-agent `config.toml` files
/// carry other tables and keys that this agent must load past. The cost is that
/// a misspelled key in those tables falls back to its default without an error.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct OtelAgentConfig {
    /// The NICo API endpoint and the certificates used to authenticate to it.
    #[serde(default)]
    pub(crate) forge_system: ForgeSystemConfig,

    /// Where to keep the obs-gateway credentials. Absent disables fetching
    /// them.
    #[serde(default)]
    pub(crate) obs_gateway: Option<ObsGatewayConfig>,

    #[serde(default)]
    pub(crate) period: PeriodConfig,
}

impl OtelAgentConfig {
    pub(crate) fn load_from(path: &Path) -> eyre::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&data)?;
        if let Some(obs_gateway) = &config.obs_gateway {
            obs_gateway.validate()?;
        }
        Ok(config)
    }
}

/// The NICo API certificates the agent authenticates with. Whatever provisions
/// them (forge-dpu-agent, or StarDrive on a site controller) owns the initial
/// files; the agent only renews them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ForgeSystemConfig {
    #[serde(default = "default_api_server")]
    pub(crate) api_server: String,
    #[serde(default = "default_root_ca")]
    pub(crate) root_ca: String,
    #[serde(default = "default_client_cert")]
    pub(crate) client_cert: String,
    #[serde(default = "default_client_key")]
    pub(crate) client_key: String,
}

impl Default for ForgeSystemConfig {
    fn default() -> Self {
        Self {
            api_server: default_api_server(),
            root_ca: default_root_ca(),
            client_cert: default_client_cert(),
            client_key: default_client_key(),
        }
    }
}

fn default_api_server() -> String {
    DEFAULT_API_SERVER.to_string()
}

fn default_root_ca() -> String {
    tls_default::default_root_ca().to_string()
}

fn default_client_cert() -> String {
    tls_default::default_client_cert().to_string()
}

fn default_client_key() -> String {
    tls_default::default_client_key().to_string()
}

/// The credentials the DPU's collector uses to export telemetry to obs-gateway.
///
/// Unlike the legacy tables, this section is new and has no deployed files to
/// stay compatible with, so unknown keys are rejected to catch a misspelled
/// setting at startup.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ObsGatewayConfig {
    /// Where the CA bundle for verifying obs-gateway is written.
    pub(crate) ca_path: PathBuf,
    /// Where the client certificate, with any intermediates, is written.
    pub(crate) client_cert_path: PathBuf,
    /// Where the client private key is written, owner-readable only.
    pub(crate) client_key_path: PathBuf,

    /// Send a CSR so the private key is generated on the DPU and never
    /// crosses the network. A source that cannot sign a CSR returns its own
    /// key, which is used instead. Off by default, so the credential source
    /// sees no request field it has not been tested with.
    #[serde(default = "default_use_csr")]
    pub(crate) use_csr: bool,

    /// Shortest wait before the next fetch. Bounds how often an unrotated
    /// credential is re-fetched.
    #[serde(default = "default_min_fetch_secs")]
    pub(crate) min_fetch_secs: u64,

    /// Longest wait before the next fetch, however long the certificate lives.
    #[serde(default = "default_max_fetch_secs")]
    pub(crate) max_fetch_secs: u64,
}

fn default_use_csr() -> bool {
    false
}

fn default_min_fetch_secs() -> u64 {
    5 * 60
}

fn default_max_fetch_secs() -> u64 {
    7 * 24 * 60 * 60
}

impl ObsGatewayConfig {
    pub(crate) fn min_fetch(&self) -> Duration {
        Duration::from_secs(self.min_fetch_secs)
    }

    pub(crate) fn max_fetch(&self) -> Duration {
        Duration::from_secs(self.max_fetch_secs)
    }

    fn validate(&self) -> eyre::Result<()> {
        for (name, path) in [
            ("ca-path", &self.ca_path),
            ("client-cert-path", &self.client_cert_path),
            ("client-key-path", &self.client_key_path),
        ] {
            eyre::ensure!(
                !path.as_os_str().is_empty(),
                "obs-gateway.{name} must not be empty"
            );
        }
        eyre::ensure!(
            self.ca_path != self.client_cert_path
                && self.ca_path != self.client_key_path
                && self.client_cert_path != self.client_key_path,
            "obs-gateway.ca-path, client-cert-path and client-key-path must be distinct files"
        );
        eyre::ensure!(
            self.min_fetch_secs >= MIN_FETCH_FLOOR_SECS,
            "obs-gateway.min-fetch-secs must be at least {MIN_FETCH_FLOOR_SECS}"
        );
        eyre::ensure!(
            self.max_fetch_secs <= MAX_FETCH_CEILING_SECS,
            "obs-gateway.max-fetch-secs must be at most {MAX_FETCH_CEILING_SECS}"
        );
        eyre::ensure!(
            self.min_fetch_secs <= self.max_fetch_secs,
            "obs-gateway.min-fetch-secs must not exceed max-fetch-secs"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct PeriodConfig {
    /// How long the main loop sleeps between iterations.
    #[serde(default = "default_main_loop_idle_secs")]
    pub(crate) main_loop_idle_secs: u64,
}

impl Default for PeriodConfig {
    fn default() -> Self {
        Self {
            main_loop_idle_secs: default_main_loop_idle_secs(),
        }
    }
}

fn default_main_loop_idle_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

    use super::*;

    /// The `config.toml` the nico-dpu-otel-agent chart renders with its default
    /// values, as asserted by `bluefield/charts/nico-dpu-otel-agent/tests`.
    const CHART_DEFAULT_CONFIG: &str = r#"
        [forge-system]
        api-server = "https://carbide-api.forge"
        root-ca = "/opt/forge/forge_root.pem"
        client-cert = "/opt/forge/machine_cert.pem"
        client-key = "/opt/forge/machine_cert.key"

        [period]
        main-loop-idle-secs = 30

        [obs-gateway]
        ca-path = "/opt/forge/obs-gateway/ca.pem"
        client-cert-path = "/opt/forge/obs-gateway/client.pem"
        client-key-path = "/opt/forge/obs-gateway/client.key"
        use-csr = false
        min-fetch-secs = 300
        max-fetch-secs = 604800
        "#;

    const OBS_PATHS: &str = r#"
        ca-path = "/obs/ca.pem"
        client-cert-path = "/obs/cert.pem"
        client-key-path = "/obs/key.pem""#;

    fn parse(toml: &str) -> eyre::Result<OtelAgentConfig> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        std::fs::write(&path, toml)?;
        OtelAgentConfig::load_from(&path)
    }

    /// Defaults and the obs-gateway section's validation, which is the part of
    /// the schema that can reject a file.
    #[test]
    fn obs_gateway_section_contract() {
        let obs = |extra: &str| format!("[obs-gateway]{OBS_PATHS}\n{extra}");
        scenarios!(
            run = |toml: String| parse(&toml)
                .map(|c| c.obs_gateway.map(|o| (o.use_csr, o.min_fetch_secs, o.max_fetch_secs)))
                .map_err(drop);
            "absent section disables the fetch" {
                String::new() => Yields(None),
            }

            "defaults" {
                obs("") => Yields(Some((false, 300, 604_800))),
            }

            "overrides" {
                obs("use-csr = true\nmin-fetch-secs = 60\nmax-fetch-secs = 3600")
                    => Yields(Some((true, 60, 3600))),
            }

            "rejected" {
                "[obs-gateway]\nca-path = \"/ca.pem\"".to_string() => Fails,
                obs("min-fetch-secs = 59") => Fails,
                obs("min-fetch-secs = 600\nmax-fetch-secs = 300") => Fails,
                obs("max-fetch-secs = 2592001") => Fails,
                obs("unknown-key = 1") => Fails,
                format!("[obs-gateway]\n{}", OBS_PATHS.replace("/obs/key.pem", "/obs/ca.pem")) => Fails,
            }
        );
    }

    /// A config file deployed for the previous agent still loads: unrelated
    /// tables and period keys are ignored and the rest keep their values.
    #[test]
    fn legacy_config_file_still_loads() {
        let config = parse(
            r#"
            [forge-system]
            api-server = "https://api.example"
            client-cert = "/c.pem"

            [machine]
            is_fake_dpu = false

            [period]
            main-loop-idle-secs = 45
            version-check-secs = 600
            "#,
        )
        .unwrap();

        assert_eq!(config.forge_system.api_server, "https://api.example");
        assert_eq!(config.forge_system.client_cert, "/c.pem");
        assert_eq!(config.forge_system.client_key, default_client_key());
        assert_eq!(config.period.main_loop_idle_secs, 45);
        assert_eq!(config.obs_gateway, None);
    }

    /// The chart's default rendering is accepted by the agent, and its NICo API
    /// and period settings are the agent's own defaults, so a site that leaves
    /// the chart alone gets the same behavior as one with no config file.
    #[test]
    fn chart_default_config_loads() {
        let config = parse(CHART_DEFAULT_CONFIG).unwrap();

        assert_eq!(config.forge_system, ForgeSystemConfig::default());
        assert_eq!(config.period, PeriodConfig::default());
        let obs_gateway = config.obs_gateway.unwrap();
        assert!(!obs_gateway.use_csr);
        assert_eq!(obs_gateway.min_fetch_secs, default_min_fetch_secs());
        assert_eq!(obs_gateway.max_fetch_secs, default_max_fetch_secs());
    }
}
