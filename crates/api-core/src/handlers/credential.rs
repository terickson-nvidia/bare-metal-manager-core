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

use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge::{self as rpc};
use carbide_nvlink_manager::DEFAULT_NMX_M_NAME;
use carbide_secrets::SecretsError;
use carbide_secrets::certificates::CertificateProvider;
use carbide_secrets::credentials::{
    BgpCredentialType, BmcCredentialType, CredentialKey, CredentialReader, CredentialType,
    Credentials, NicLockdownIkm,
};
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use model::ConfigValidationError;
use model::ib::DEFAULT_IB_FABRIC_NAME;
use tonic::{Request, Response, Status};
use x509_parser::prelude::{FromDer, X509Certificate, X509CertificationRequest};

use crate::CarbideError;
use crate::api::Api;
use crate::cfg::file::{ObsGatewayCredentialSource, ObsGatewayCredentialsConfig};
use crate::credentials::UpdateCredentials;
use crate::handlers::utils::convert_and_log_machine_id;

/// We assume that all BMCs speak Redfish on the standard port
const BMC_REDFISH_PORT: u16 = 443;

/// Default Username for the admin BMC account.
const DEFAULT_FORGE_ADMIN_BMC_USERNAME: &str = "root";

/// The maximum size that will be accepted in the underlying BGP config
/// on the DPU.  This was directly verified by checking the maximum accepted
/// by FRR on the DPU.  NVUE will silently accept seemingly any length,
/// but FRR reloads fail above this length.
pub(crate) const MAX_BGP_PASSWORD_LENGTH: usize = 80;
const MISSING_FIRMWARE_ARTIFACT_CREDENTIAL_NAME: &str =
    "firmware artifact access token credential name is required";

pub(crate) async fn create_credential(
    api: &Api,
    request: tonic::Request<rpc::CredentialCreationRequest>,
) -> Result<tonic::Response<rpc::CredentialCreationResult>, tonic::Status> {
    // Do not log_request_data as credentials contain sensitive information
    // crate::api::log_request_data(&request);

    let req = request.into_inner();
    let password = req.password;

    let credential_type = rpc::CredentialType::try_from(req.credential_type).map_err(|_| {
        CarbideError::NotFoundError {
            kind: "credential_type",
            id: req.credential_type.to_string(),
        }
    })?;

    match credential_type {
        rpc::CredentialType::HostBmc | rpc::CredentialType::Dpubmc => {
            return Err(CarbideError::InvalidArgument(
                "forge no longer maintains separate paths for host and DPU site-wide BMC root credentials. this has been unified".into(),
            ).into());
        }
        rpc::CredentialType::SiteWideBmcRoot => {
            if password.is_empty() {
                return Err(CarbideError::InvalidArgument(
                    "site-wide BMC root password must not be empty".to_string(),
                )
                .into());
            }
            set_sitewide_bmc_root_credentials(api, password).await?;
            if let Err(error) =
                crate::dpa::lockdown::ensure_lockdown_ikm_seeded(&*api.credential_manager).await
            {
                // The requested credential write is already durable. Startup
                // installs a retry task for this idempotent compatibility seed,
                // so returning an RPC error would incorrectly invite the caller
                // to repeat a write that already succeeded.
                tracing::warn!(
                    error = %error,
                    "site-wide BMC root was stored; initial NIC lockdown IKM seeding is deferred to the background retry"
                );
            }
        }
        rpc::CredentialType::SiteWideNicLockdownIkm => {
            set_sitewide_nic_lockdown_ikm(api, password)
                .await
                .map_err(|e| {
                    CarbideError::internal(format!(
                        "error setting site wide NIC lockdown IKM: {e:?} "
                    ))
                })?;
        }
        rpc::CredentialType::Ufm => {
            if let Some(username) = req.username {
                api.credential_manager
                    .set_credentials(
                        &CredentialKey::UfmAuth {
                            fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                        },
                        &Credentials::UsernamePassword {
                            username: username.clone(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|error| {
                        map_credential_mutation_error(
                            format!("error setting credential for ufm {username}"),
                            error,
                        )
                    })?;
            } else if req.username.is_none() && password.is_empty() && req.vendor.is_some() {
                write_ufm_certs(api, req.vendor.unwrap_or_default()).await?;
            } else {
                return Err(CarbideError::InvalidArgument("missing UFM url".to_string()).into());
            }
        }
        rpc::CredentialType::DpuUefi => {
            if (api
                .credential_manager
                .get_credentials(&CredentialKey::DpuUefi {
                    credential_type: CredentialType::SiteDefault,
                })
                .await)
                .is_ok_and(|result| {
                    result.is_some_and(|creds| {
                        // An empty password is seeded by nico-prereqs at deploy time —
                        // treat it as absent so the operator can set the real password.
                        let Credentials::UsernamePassword { ref password, .. } = creds;
                        !password.is_empty()
                    })
                })
            {
                // TODO: support reset credential
                return Err(tonic::Status::already_exists(
                    "not support to reset DPU UEFI credential",
                ));
            }
            api.credential_manager
                .set_credentials(
                    &CredentialKey::DpuUefi {
                        credential_type: CredentialType::SiteDefault,
                    },
                    &Credentials::UsernamePassword {
                        username: "".to_string(),
                        password: password.clone(),
                    },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("error setting credential for DPU UEFI: {e:?} "))
                })?
        }
        rpc::CredentialType::HostUefi => {
            if api
                .credential_manager
                .get_credentials(&CredentialKey::HostUefi {
                    credential_type: CredentialType::SiteDefault,
                })
                .await
                .is_ok_and(|result| {
                    result.is_some_and(|creds| {
                        // An empty password is seeded by nico-prereqs at deploy time —
                        // treat it as absent so the operator can set the real password.
                        let Credentials::UsernamePassword { ref password, .. } = creds;
                        !password.is_empty()
                    })
                })
            {
                // TODO: support reset credential
                return Err(tonic::Status::already_exists(
                    "resetting the host UEFI credentials in vault is not supported",
                ));
            }
            api.credential_manager
                .set_credentials(
                    &CredentialKey::HostUefi {
                        credential_type: CredentialType::SiteDefault,
                    },
                    &Credentials::UsernamePassword {
                        username: "".to_string(),
                        password: password.clone(),
                    },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("error setting credential for host UEFI: {e:?}"))
                })?
        }
        rpc::CredentialType::HostBmcFactoryDefault => {
            let Some(username) = req.username else {
                return Err(CarbideError::InvalidArgument("missing username".to_string()).into());
            };
            let Some(vendor) = req.vendor else {
                return Err(CarbideError::InvalidArgument("missing vendor".to_string()).into());
            };
            let vendor: bmc_vendor::BMCVendor = vendor.as_str().into();
            api.credential_manager
                .set_credentials(
                    &CredentialKey::HostRedfish {
                        credential_type: CredentialType::HostHardwareDefault { vendor },
                    },
                    &Credentials::UsernamePassword { username, password },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!(
                        "error setting host factory default credential: {e:?}"
                    ))
                })?
        }
        rpc::CredentialType::DpuBmcFactoryDefault => {
            let Some(username) = req.username else {
                return Err(CarbideError::InvalidArgument("missing username".to_string()).into());
            };
            // Reuse the proto `vendor` field to carry the DPU model. Absent/empty
            // means the catch-all default (backward compatible). `DpuModel::from`
            // maps anything unrecognized to `Unknown`, so only accept that when the
            // caller explicitly asked for the catch-all -- otherwise it's a typo and
            // we reject it rather than silently writing to the legacy `root` path.
            let model: bmc_vendor::DpuModel = match req.vendor.as_deref() {
                None | Some("") => bmc_vendor::DpuModel::Unknown,
                Some(vendor) => {
                    let model = bmc_vendor::DpuModel::from(vendor);
                    if model == bmc_vendor::DpuModel::Unknown
                        && !vendor.eq_ignore_ascii_case("unknown")
                    {
                        return Err(CarbideError::InvalidArgument(format!(
                            "unrecognized DPU model {vendor:?}; expected one of bf2, bf3, bf4, unknown"
                        ))
                        .into());
                    }
                    model
                }
            };
            api.credential_manager
                .set_credentials(
                    &CredentialKey::DpuRedfish {
                        credential_type: CredentialType::DpuHardwareDefault { model },
                    },
                    &Credentials::UsernamePassword { username, password },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!(
                        "error setting DPU factory default credential: {e:?}"
                    ))
                })?
        }
        rpc::CredentialType::RootBmcByMacAddress => {
            let Some(mac_address) = req.mac_address else {
                return Err(CarbideError::InvalidArgument("mac address".to_string()).into());
            };

            let parsed_mac: MacAddress = mac_address
                .parse::<MacAddress>()
                .map_err(CarbideError::from)?;

            set_bmc_root_credentials_by_mac(api, parsed_mac, password, req.username)
                .await
                .map_err(|e| {
                    CarbideError::internal(format!(
                        "error setting site wide BMC root credentials: {e:?} "
                    ))
                })?;
        }
        rpc::CredentialType::BmcForgeAdminByMacAddress => {
            // TODO: support credential creation for forge-admin
            return Err(CarbideError::InvalidArgument(
                "forge does not support creating forge-admin credentials yet".into(),
            )
            .into());
        }
        rpc::CredentialType::NmxM => {
            if let Some(username) = req.username {
                api.credential_manager
                    .set_credentials(
                        &CredentialKey::NmxM {
                            nmxm_id: DEFAULT_NMX_M_NAME.to_string(),
                        },
                        &Credentials::UsernamePassword {
                            username: username.clone(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::internal(format!(
                            "error setting credential for NmxM {}: {:?} ",
                            username.clone(),
                            e
                        ))
                    })?;
            } else {
                return Err(CarbideError::InvalidArgument("missing username".to_string()).into());
            }
        }
        rpc::CredentialType::BgpSiteWideLeafPassword => {
            api.credential_manager
                .set_credentials(
                    &CredentialKey::Bgp {
                        credential_type: BgpCredentialType::SiteWideLeafPassword,
                    },
                    &Credentials::UsernamePassword {
                        username: "".to_string(),
                        password: if password.len() <= MAX_BGP_PASSWORD_LENGTH {
                            password
                        } else {
                            return Err(CarbideError::InvalidConfiguration(ConfigValidationError::InvalidValue(format!("BGP password length exceeds {MAX_BGP_PASSWORD_LENGTH} characters"))).into())
                        },
                    },
                )
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("error setting BGP credential: {e:?}"))
                })?;
        }
        rpc::CredentialType::FirmwareArtifactAccessToken => {
            let name = req
                .credential_name
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    CarbideError::InvalidArgument(MISSING_FIRMWARE_ARTIFACT_CREDENTIAL_NAME.into())
                })?;

            if password.is_empty() {
                return Err(CarbideError::InvalidArgument(
                    "firmware artifact access token must not be empty".to_string(),
                )
                .into());
            }

            let key = CredentialKey::FirmwareArtifactAccessToken { name };

            // Artifact tokens are opaque, while the credential store uses a
            // username/password record. The empty username has no authentication
            // meaning, and set_credentials replaces a token with the same name.
            api.credential_manager
                .set_credentials(&key, &Credentials::new("", password))
                .await
                .map_err(|error| {
                    CarbideError::internal(format!(
                        "error setting firmware artifact access token credential: {error:?}"
                    ))
                })?;
        }
    };

    Ok(Response::new(rpc::CredentialCreationResult {}))
}

pub(crate) async fn delete_credential(
    api: &Api,
    request: tonic::Request<rpc::CredentialDeletionRequest>,
) -> Result<tonic::Response<rpc::CredentialDeletionResult>, tonic::Status> {
    crate::api::log_request_data(&request);
    let req = request.into_inner();

    let credential_type = rpc::CredentialType::try_from(req.credential_type).map_err(|_| {
        CarbideError::NotFoundError {
            kind: "credential_type",
            id: req.credential_type.to_string(),
        }
    })?;

    match credential_type {
        rpc::CredentialType::Ufm => {
            if let Some(username) = req.username {
                api.credential_manager
                    .set_credentials(
                        &CredentialKey::UfmAuth {
                            fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                        },
                        &Credentials::UsernamePassword {
                            username: username.clone(),
                            password: "".to_string(),
                        },
                    )
                    .await
                    .map_err(|error| {
                        map_credential_mutation_error(
                            format!("error deleting credential for ufm {username}"),
                            error,
                        )
                    })?;
            } else {
                return Err(CarbideError::InvalidArgument("missing UFM url".to_string()).into());
            }
        }
        rpc::CredentialType::SiteWideBmcRoot => {
            // TODO: actually delete entry from vault instead of setting to empty string
            set_sitewide_bmc_root_credentials(api, "".to_string()).await?;
        }
        rpc::CredentialType::RootBmcByMacAddress => match req.mac_address {
            Some(mac_address) => {
                let parsed_mac: MacAddress = mac_address
                    .parse::<MacAddress>()
                    .map_err(CarbideError::from)?;

                delete_bmc_root_credentials_by_mac(api, parsed_mac).await?;
                api.bmc_session_manager.flush_mac(parsed_mac).await;
            }
            None => {
                return Err(CarbideError::InvalidArgument(
                    "request does not specify mac address".into(),
                )
                .into());
            }
        },
        rpc::CredentialType::HostBmc
        | rpc::CredentialType::Dpubmc
        | rpc::CredentialType::DpuUefi
        | rpc::CredentialType::HostUefi
        | rpc::CredentialType::HostBmcFactoryDefault
        | rpc::CredentialType::DpuBmcFactoryDefault
        | rpc::CredentialType::BmcForgeAdminByMacAddress
        | rpc::CredentialType::NmxM
        // Deleting the lockdown IKM would break NIC unlock; rotate it instead.
        | rpc::CredentialType::SiteWideNicLockdownIkm => {
            // Not support delete credential for these types
        }
        rpc::CredentialType::BgpSiteWideLeafPassword => {
            api.credential_manager
                .delete_credentials(&CredentialKey::Bgp {
                    credential_type: BgpCredentialType::SiteWideLeafPassword,
                })
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("error deleting BGP credential: {e:?}"))
                })?;
        }
        rpc::CredentialType::FirmwareArtifactAccessToken => {
            let name = req
                .credential_name
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    CarbideError::InvalidArgument(MISSING_FIRMWARE_ARTIFACT_CREDENTIAL_NAME.into())
                })?;

            api.credential_manager
                .delete_credentials(&CredentialKey::FirmwareArtifactAccessToken { name })
                .await
                .map_err(|error| {
                    CarbideError::internal(format!(
                        "error deleting firmware artifact access token credential: {error:?}"
                    ))
                })?;
        }
    };

    Ok(Response::new(rpc::CredentialDeletionResult {}))
}

fn map_credential_mutation_error(context: String, error: SecretsError) -> CarbideError {
    match error {
        error @ (SecretsError::UfmCredentialMutationBlocked { .. }
        | SecretsError::BmcSiteWideRootV0CredentialMutationBlocked) => {
            CarbideError::FailedPrecondition(error.to_string())
        }
        error => CarbideError::internal(format!("{context}: {error:?}")),
    }
}

pub(crate) async fn update_machine_credentials(
    api: &Api,
    request: tonic::Request<rpc::MachineCredentialsUpdateRequest>,
) -> Result<Response<rpc::MachineCredentialsUpdateResponse>, tonic::Status> {
    // Note that we don't log the request here via `log_request_data`.
    // Doing that would make credentials show up in the log stream
    tracing::Span::current().record("request", "MachineCredentialsUpdateRequest { }");

    let request = request.into_inner();
    let machine_id: MachineId = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let mac_address = match request.mac_address {
        Some(v) => Some(v.parse().map_err(|_| {
            CarbideError::from(RpcDataConversionError::InvalidMacAddress(
                "mac_address".into(),
            ))
        })?),
        None => None,
    };

    let update = UpdateCredentials {
        machine_id,
        mac_address,
        credentials: request.credentials,
    };

    let updates_bmc_credentials = update.credentials.iter().any(|credential| {
        matches!(
            rpc::machine_credentials_update_request::CredentialPurpose::try_from(
                credential.credential_purpose
            ),
            Ok(rpc::machine_credentials_update_request::CredentialPurpose::Bmc)
        )
    });

    let response = update.execute(api.credential_manager.as_ref()).await?;

    if updates_bmc_credentials && let Some(bmc_mac_address) = update.mac_address {
        api.bmc_session_manager
            .note_credentials_updated(bmc_mac_address)
            .await;
    }

    Ok(Response::new(response))
}

/// Issue BMC credentials for the SPIFFE service identity making this call.
///
/// In the default configuration this rotates a Redfish session token (see
/// [`crate::credentials::BmcSessionManager::rotate`]). When the runtime
/// config enables `allow_bmc_basic_auth_fallback`, BMCs that do not expose
/// Redfish `SessionService` instead receive their stored `UsernamePassword`
/// credentials; the wire `oneof` already supports both shapes so callers do
/// not need to opt in. Callers without a SPIFFE service identity are
/// rejected with `PermissionDenied`.
pub(crate) async fn get_bmc_credentals(
    api: &Api,
    request: tonic::Request<rpc::GetBmcCredentialsRequest>,
) -> Result<Response<rpc::GetBmcCredentialsResponse>, tonic::Status> {
    crate::api::log_request_data(&request);

    let spiffe_service_id = request
        .extensions()
        .get::<crate::auth::AuthContext>()
        .and_then(|ctx| ctx.get_spiffe_service_id())
        .ok_or_else(|| {
            Status::permission_denied(
                "BMC credentials are only issued to SPIFFE service identities",
            )
        })?
        .to_owned();

    let req = request.into_inner();

    let bmc_mac_address: mac_address::MacAddress = req
        .mac_addr
        .parse()
        .map_err(CarbideError::MacAddressParseError)?;

    let bmc_ips = db::machine_interface::lookup_bmc_ip_by_mac_address(
        &api.database_connection,
        bmc_mac_address,
    )
    .await?;

    let bmc_ip = bmc_ips
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| bmc_ips.first().copied())
        .ok_or_else(|| {
            Status::not_found(format!(
                "no BMC IP addresses recorded for MAC {bmc_mac_address}"
            ))
        })?;

    let bmc_addr = SocketAddr::new(bmc_ip, BMC_REDFISH_PORT);

    let material = api
        .bmc_session_manager
        .issue_credentials(&spiffe_service_id, bmc_mac_address, bmc_addr)
        .await
        .map_err(|err| match err {
            crate::credentials::BmcSessionError::AvoidLockout { .. }
            | crate::credentials::BmcSessionError::NoSessionService { .. }
            | crate::credentials::BmcSessionError::MissingRootCredentials(_) => {
                // These are "we refuse to attempt session creation" outcomes
                // that the operator can resolve (configure/rotate creds, or
                // flip the basic-auth-fallback flag). FailedPrecondition
                // matches the gRPC semantics: the request is well-formed but
                // the server-side state forbids it.
                Status::failed_precondition(err.to_string())
            }
            crate::credentials::BmcSessionError::Store(_) => Status::internal(err.to_string()),
            other => CarbideError::internal(other.to_string()).into(),
        })?;

    let credentials_type = match material {
        crate::credentials::BmcAuthMaterial::Session(entry) => {
            rpc::bmc_credentials::Type::SessionToken(rpc::SessionToken { token: entry.token })
        }
        crate::credentials::BmcAuthMaterial::Basic(Credentials::UsernamePassword {
            username,
            password,
        }) => rpc::bmc_credentials::Type::UsernamePassword(rpc::UsernamePassword {
            username,
            password,
        }),
    };

    Ok(Response::new(rpc::GetBmcCredentialsResponse {
        credentials: Some(rpc::BmcCredentials {
            r#type: Some(credentials_type),
        }),
    }))
}

pub(crate) async fn get_switch_nvos_credentials(
    api: &Api,
    request: tonic::Request<rpc::GetSwitchNvosCredentialsRequest>,
) -> Result<Response<rpc::GetBmcCredentialsResponse>, tonic::Status> {
    crate::api::log_request_data(&request);

    let req = request.into_inner();
    let switch_id = req
        .switch_id
        .ok_or_else(|| CarbideError::InvalidArgument("switch_id is required".to_string()))?;

    let bmc_mac_address = {
        let mut txn = api.txn_begin().await?;
        let switches = db::switch::find_by(
            &mut txn,
            db::ObjectColumnFilter::One(db::switch::IdColumn, &switch_id),
        )
        .await?;
        txn.rollback_or_log("read-only load of switch for credential lookup")
            .await;

        let switch = switches
            .first()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "switch",
                id: switch_id.to_string(),
            })?;

        switch
            .bmc_mac_address
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "switch_bmc_mac_address",
                id: switch_id.to_string(),
            })?
    };

    let credentials = api
        .credential_manager
        .get_credentials(&CredentialKey::SwitchNvosAdmin { bmc_mac_address })
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "switch_nvos_credentials",
            id: switch_id.to_string(),
        })?;

    let Credentials::UsernamePassword { username, password } = credentials;

    Ok(Response::new(rpc::GetBmcCredentialsResponse {
        credentials: Some(rpc::BmcCredentials {
            r#type: Some(rpc::bmc_credentials::Type::UsernamePassword(
                rpc::UsernamePassword { username, password },
            )),
        }),
    }))
}

async fn set_sitewide_bmc_root_credentials(
    api: &Api,
    password: String,
) -> Result<(), CarbideError> {
    let credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::SiteWideRoot,
    };

    let credentials = Credentials::UsernamePassword {
        // we no longer set a site-wide bmc username
        username: "".to_string(),
        password: password.clone(),
    };

    set_bmc_credentials(api, &credential_key, &credentials).await
}

// set_sitewide_nic_lockdown_ikm writes the dedicated site-wide SuperNIC
// lockdown IKM. This lets an SRE configure (or rotate) the lockdown key
// independently of the BMC root at site bring-up, mirroring how the site-wide
// BMC root is set.
async fn set_sitewide_nic_lockdown_ikm(api: &Api, password: String) -> Result<(), CarbideError> {
    let credential_key = CredentialKey::NicLockdownIkm {
        credential_type: NicLockdownIkm::SiteWide {
            version: crate::dpa::lockdown::SEED_LOCKDOWN_IKM_VERSION,
        },
    };

    let credentials = Credentials::UsernamePassword {
        username: "".to_string(),
        password,
    };

    api.credential_manager
        .set_credentials(&credential_key, &credentials)
        .await
        .map_err(|e| {
            CarbideError::internal(format!("error setting NIC lockdown IKM credential: {e:?}"))
        })
}

pub(super) async fn delete_bmc_root_credentials_by_mac(
    api: &Api,
    bmc_mac_address: MacAddress,
) -> Result<(), CarbideError> {
    let credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
    };

    api.credential_manager
        .delete_credentials(&credential_key)
        .await
        .map_err(|e| {
            CarbideError::internal(format!("error deleting credential for BMC: {e:?} "))
        })?;

    // Drop the bmc convergence marker alongside the Vault secret it depends on:
    // once NICo discards the per-device BMC secret it can no longer authenticate
    // or rotate the device, so tracking convergence is meaningless. (The rotation
    // engine also joins device_credential_rotation to the live device tables, so
    // a row orphaned by device deletion is never acted on -- this just keeps the
    // table tidy at the chokepoint where the secret actually goes away.)
    let mut txn = api.txn_begin().await?;
    db::credential_rotation::delete_device_converged(
        &mut txn,
        bmc_mac_address,
        db::credential_rotation::CredentialRotationType::Bmc,
    )
    .await?;
    txn.commit().await?;

    api.bmc_session_manager.flush_mac(bmc_mac_address).await;

    Ok(())
}

async fn set_bmc_root_credentials_by_mac(
    api: &Api,
    bmc_mac_address: MacAddress,
    password: String,
    username: Option<String>,
) -> Result<(), CarbideError> {
    let credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
    };

    let credentials = Credentials::UsernamePassword {
        username: username.unwrap_or_else(|| DEFAULT_FORGE_ADMIN_BMC_USERNAME.to_string()),
        password: password.clone(),
    };

    set_bmc_credentials(api, &credential_key, &credentials).await?;

    // Reset breaker
    api.bmc_session_manager
        .note_credentials_updated(bmc_mac_address)
        .await;

    Ok(())
}

async fn set_bmc_credentials(
    api: &Api,
    credential_key: &CredentialKey,
    credentials: &Credentials,
) -> Result<(), CarbideError> {
    api.credential_manager
        .set_credentials(credential_key, credentials)
        .await
        .map_err(|error| {
            map_credential_mutation_error("error setting credential for BMC".to_string(), error)
        })
}

async fn write_ufm_certs(api: &Api, fabric: String) -> Result<(), CarbideError> {
    const CERT_PATH: &str = "/var/run/secrets";

    // ttl can be limited by vault, so final value can be different
    // alternative names should match vault`s `allowed_domains` parameter
    // See: forged:bases/argo-workflows/workflows/vault/configure-vault.yaml
    let ttl = "365d".to_string();
    let alt_names = if let Some(value) = &api.runtime_config.initial_domain_name {
        format!("{fabric}.ufm.forge, {fabric}.ufm.{value}")
    } else {
        format!("{fabric}.ufm.forge")
    };

    let certificate = api
        .certificate_provider
        .get_certificate(fabric.as_str(), Some(alt_names), Some(ttl))
        .await
        .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?;

    let mut cert_filename = format!("{CERT_PATH}/{fabric}-ufm-ca-intermediate.crt");
    let mut cert_file = File::create(cert_filename.clone()).map_err(|e| {
        CarbideError::internal(format!("could not create: {cert_filename} err: {e:?}"))
    })?;
    cert_file
        .write_all(certificate.issuing_ca.as_slice())
        .map_err(|e| {
            CarbideError::internal(format!(
                "failed to write certificate to: {cert_filename} error: {e:?}"
            ))
        })?;

    cert_filename = format!("{CERT_PATH}/{fabric}-ufm-server.key");
    cert_file = File::create(cert_filename.clone()).map_err(|e| {
        CarbideError::internal(format!("could not create: {cert_filename} err: {e:?}"))
    })?;
    cert_file
        .write_all(certificate.private_key.as_slice())
        .map_err(|e| {
            CarbideError::internal(format!(
                "failed to write certificate to: {cert_filename} error: {e:?}"
            ))
        })?;

    cert_filename = format!("{CERT_PATH}/{fabric}-ufm-server.crt");
    cert_file = File::create(cert_filename.clone()).map_err(|e| {
        CarbideError::internal(format!("could not create: {cert_filename} err: {e:?}"))
    })?;
    cert_file
        .write_all(certificate.public_key.as_slice())
        .map_err(|e| {
            CarbideError::internal(format!(
                "failed to write certificate to: {cert_filename} error: {e:?}"
            ))
        })?;

    Ok(())
}

pub(crate) async fn renew_machine_certificate(
    api: &Api,
    request: Request<rpc::MachineCertificateRenewRequest>,
) -> Result<Response<rpc::MachineCertificateResult>, Status> {
    if let Some(machine_identity) = request
        .extensions()
        .get::<crate::auth::AuthContext>()
        .and_then(|auth_context| auth_context.get_spiffe_machine_id())
    {
        let certificate = api
            .certificate_provider
            .get_certificate(machine_identity, None, None)
            .await
            .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?;

        return Ok(Response::new(rpc::MachineCertificateResult {
            machine_certificate: Some(certificate.into()),
        }));
    }

    Err(CarbideError::ClientCertificateError("no client certificate presented?".to_string()).into())
}

pub(crate) async fn get_obs_gateway_credentials(
    api: &Api,
    request: Request<rpc::GetObsGatewayCredentialsRequest>,
) -> Result<Response<rpc::GetObsGatewayCredentialsResponse>, Status> {
    // Credentials are sensitive: do not log request or response data.
    // The identity comes from the TLS channel, never from the request.
    let machine_id = crate::auth::authenticated_machine_id(&request)?.ok_or_else(|| {
        CarbideError::ClientCertificateError("no client certificate presented?".into())
    })?;
    let request = request.into_inner();

    // Static files exist for sites whose obs-gateway does not accept
    // certificates from the site CA.
    let response = match &api.runtime_config.obs_gateway_credentials {
        ObsGatewayCredentialSource::StaticFiles(config) => {
            read_obs_gateway_credentials(config).await?
        }
        ObsGatewayCredentialSource::SiteCa {} => {
            issue_site_ca_credentials(
                api.certificate_provider.as_ref(),
                &machine_id.to_string(),
                request.csr_pem.as_deref(),
            )
            .await?
        }
    };
    Ok(Response::new(response))
}

/// Issues credentials for `machine_id` from the same CA that issues its NICo API
/// certificate, so a site without a dedicated obs-gateway can keep exporting to
/// a receiver that trusts the site CA. With a CSR the private key stays with
/// the caller; without one the provider generates it.
async fn issue_site_ca_credentials(
    provider: &dyn CertificateProvider,
    machine_id: &str,
    csr_pem: Option<&str>,
) -> Result<rpc::GetObsGatewayCredentialsResponse, CarbideError> {
    let certificate = match csr_pem {
        Some(csr_pem) => {
            validate_csr(csr_pem)?;
            provider.sign_certificate(machine_id, csr_pem).await
        }
        None => provider.get_certificate(machine_id, None, None).await,
    }
    .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?;

    let pem = |name: &str, bytes: Vec<u8>| {
        String::from_utf8(bytes)
            .map_err(|e| CarbideError::internal(format!("{name} is not valid PEM text: {e}")))
    };
    let client_cert_pem = pem("client certificate", certificate.public_key)?;
    let not_after = leaf_not_after(&client_cert_pem)?;
    let client_key_pem =
        Some(pem("client key", certificate.private_key)?).filter(|k| !k.is_empty());

    Ok(rpc::GetObsGatewayCredentialsResponse {
        ca_pem: pem("issuing CA", certificate.issuing_ca)?,
        client_cert_pem,
        client_key_pem,
        not_after: Some(not_after),
    })
}

/// Rejects a CSR that is not a well-formed PEM PKCS#10 request or whose
/// signature does not verify, so the caller proves it holds the private key.
fn validate_csr(csr_pem: &str) -> Result<(), CarbideError> {
    let invalid =
        |e: &dyn std::fmt::Display| CarbideError::InvalidArgument(format!("csr_pem: {e}"));
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes()).map_err(|e| invalid(&e))?;
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents).map_err(|e| invalid(&e))?;
    csr.verify_signature().map_err(|e| invalid(&e))
}

/// Reads the files named by `config`. Separate from the handler so it can run
/// without an `Api`.
async fn read_obs_gateway_credentials(
    config: &ObsGatewayCredentialsConfig,
) -> Result<rpc::GetObsGatewayCredentialsResponse, CarbideError> {
    async fn read(path: &Path) -> Result<String, CarbideError> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| CarbideError::internal(format!("read {}: {e}", path.display())))
    }

    let ca_pem = read(&config.ca_file).await?;
    let client_cert_pem = read(&config.client_cert_file).await?;
    let client_key_pem = read(&config.client_key_file).await?;
    let not_after = leaf_not_after(&client_cert_pem)?;

    Ok(rpc::GetObsGatewayCredentialsResponse {
        ca_pem,
        client_cert_pem,
        client_key_pem: Some(client_key_pem),
        not_after: Some(not_after),
    })
}

/// Expiry of the first certificate in `cert_pem`, the leaf by convention.
fn leaf_not_after(cert_pem: &str) -> Result<::rpc::Timestamp, CarbideError> {
    let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or_else(|| CarbideError::internal("client certificate PEM has no certificate".into()))?
        .map_err(|e| CarbideError::internal(format!("parse client certificate PEM: {e}")))?;
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|e| CarbideError::internal(format!("parse client certificate: {e}")))?;
    let not_after = chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or_else(|| CarbideError::internal("client certificate expiry out of range".into()))?;
    Ok(not_after.into())
}

pub(crate) async fn get_container_registry_credential(
    api: &Api,
    request: Request<rpc::GetContainerRegistryCredentialRequest>,
) -> Result<Response<rpc::GetContainerRegistryCredentialResponse>, Status> {
    let registry = request.into_inner().registry;
    if registry.is_empty() {
        return Err(CarbideError::InvalidArgument("registry must not be empty".into()).into());
    }
    let key = CredentialKey::ContainerRegistry {
        registry: registry.clone(),
    };
    match api
        .credential_manager
        .get_credentials(&key)
        .await
        .map_err(|e| CarbideError::internal(format!("get registry credential: {e:?}")))?
    {
        Some(Credentials::UsernamePassword { username, password }) => {
            Ok(Response::new(rpc::GetContainerRegistryCredentialResponse {
                username,
                password,
            }))
        }
        None => Err(CarbideError::NotFoundError {
            kind: "container_registry_credential",
            id: registry,
        }
        .into()),
    }
}

pub(crate) async fn set_container_registry_credential(
    api: &Api,
    request: Request<rpc::SetContainerRegistryCredentialRequest>,
) -> Result<Response<()>, Status> {
    // Credentials are sensitive — do not log request data.
    let req = request.into_inner();
    if req.registry.is_empty() {
        return Err(CarbideError::InvalidArgument("registry must not be empty".into()).into());
    }
    let key = CredentialKey::ContainerRegistry {
        registry: req.registry,
    };
    api.credential_manager
        .set_credentials(
            &key,
            &Credentials::UsernamePassword {
                username: req.username,
                password: req.password,
            },
        )
        .await
        .map_err(|e| CarbideError::internal(format!("set registry credential: {e:?}")))?;
    Ok(Response::new(()))
}

#[cfg(test)]
mod obs_gateway_credentials_tests {
    use super::*;

    const CA_PEM: &str = "ca bundle\n";
    const KEY_PEM: &str = "key material\n";

    type BreakFiles = fn(&ObsGatewayCredentialsConfig);

    fn cert_pem_expiring(year: i32) -> String {
        let mut params = rcgen::CertificateParams::default();
        params.not_after = rcgen::date_time_ymd(year, 1, 2);
        params
            .self_signed(&rcgen::KeyPair::generate().expect("test key generates"))
            .expect("test cert signs")
            .pem()
    }

    fn write_files(dir: &Path, cert_pem: &str) -> ObsGatewayCredentialsConfig {
        let config = ObsGatewayCredentialsConfig {
            ca_file: dir.join("ca.pem"),
            client_cert_file: dir.join("tls.crt"),
            client_key_file: dir.join("tls.key"),
        };
        std::fs::write(&config.ca_file, CA_PEM).unwrap();
        std::fs::write(&config.client_cert_file, cert_pem).unwrap();
        std::fs::write(&config.client_key_file, KEY_PEM).unwrap();
        config
    }

    /// The response carries the files verbatim, with the leaf's expiry as
    /// `not_after`.
    #[tokio::test]
    async fn returns_files_and_leaf_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let cert_pem = cert_pem_expiring(2030);
        let config = write_files(dir.path(), &cert_pem);

        let response = read_obs_gateway_credentials(&config).await.unwrap();

        assert_eq!(response.ca_pem, CA_PEM);
        assert_eq!(response.client_cert_pem, cert_pem);
        assert_eq!(response.client_key_pem.as_deref(), Some(KEY_PEM));
        // 2030-01-02T00:00:00Z
        assert_eq!(response.not_after.unwrap().seconds, 1_893_542_400);
    }

    /// Each failure surfaces as an error instead of a partial response.
    #[tokio::test]
    async fn fails_on_unreadable_or_unparseable_files() {
        let cases: [(&str, BreakFiles); 3] = [
            ("missing ca file", |c| {
                std::fs::remove_file(&c.ca_file).unwrap()
            }),
            ("missing key file", |c| {
                std::fs::remove_file(&c.client_key_file).unwrap()
            }),
            ("cert file without a certificate", |c| {
                std::fs::write(&c.client_cert_file, "not pem").unwrap()
            }),
        ];
        for (scenario, break_files) in cases {
            let dir = tempfile::tempdir().unwrap();
            let config = write_files(dir.path(), &cert_pem_expiring(2030));
            break_files(&config);

            let result = read_obs_gateway_credentials(&config).await;

            assert!(result.is_err(), "{scenario}: expected an error");
        }
    }

    fn csr_pem() -> String {
        rcgen::CertificateParams::default()
            .serialize_request(&rcgen::KeyPair::generate().expect("test key generates"))
            .expect("test csr signs")
            .pem()
            .expect("test csr encodes")
    }

    fn provider_issuing(
        cert_pem: String,
        key_pem: &str,
    ) -> carbide_secrets::test_support::certificates::TestCertificateProvider {
        let provider = carbide_secrets::test_support::certificates::TestCertificateProvider::new();
        provider.certificates.try_lock().unwrap().insert(
            "machine-1".to_string(),
            carbide_secrets::certificates::Certificate {
                issuing_ca: CA_PEM.as_bytes().to_vec(),
                private_key: key_pem.as_bytes().to_vec(),
                public_key: cert_pem.into_bytes(),
            },
        );
        provider
    }

    /// Only the key-generating path returns a private key; a CSR keeps the key
    /// with the caller and the response says so by leaving it unset.
    #[tokio::test]
    async fn site_ca_credentials_return_a_key_only_without_a_csr() {
        let provider = provider_issuing(cert_pem_expiring(2030), KEY_PEM);
        let csr = csr_pem();
        let cases = [
            ("no csr", None, Some(KEY_PEM)),
            ("csr", Some(csr.as_str()), None),
        ];
        for (scenario, csr_pem, expected_key) in cases {
            let response = issue_site_ca_credentials(&provider, "machine-1", csr_pem)
                .await
                .unwrap();

            assert_eq!(response.ca_pem, CA_PEM, "{scenario}");
            assert_eq!(
                response.client_key_pem.as_deref(),
                expected_key,
                "{scenario}"
            );
            assert_eq!(
                response.not_after.unwrap().seconds,
                1_893_542_400,
                "{scenario}"
            );
        }
    }

    /// A CSR that does not parse is rejected before it reaches the issuer.
    #[tokio::test]
    async fn site_ca_credentials_reject_an_unparseable_csr() {
        let provider = provider_issuing(cert_pem_expiring(2030), KEY_PEM);

        let result = issue_site_ca_credentials(&provider, "machine-1", Some("not pem")).await;

        assert!(matches!(result, Err(CarbideError::InvalidArgument(_))));
    }
}
