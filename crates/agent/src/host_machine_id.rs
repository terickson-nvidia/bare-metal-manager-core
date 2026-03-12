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
use backon::{ExponentialBuilder, Retryable};
use core::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use forge_dpu_agent_utils::utils::create_forge_client;
use rpc::forge::InterfaceList;
use rpc::forge_tls_client::{ForgeClientConfig, ForgeClientT};

use crate::periodic_config_fetcher::PeriodicConfigFetcher;

async fn get_interface_list(
    client: &mut ForgeClientT,
    interface: MachineInterfaceId,
) -> Result<InterfaceList, eyre::Error> {
    let request = tonic::Request::new(rpc::forge::InterfaceSearchQuery {
        id: Some(interface),
        ip: None,
    });

    match client.find_interfaces(request).await {
        Ok(response) => Ok(response.into_inner()),
        Err(err) => {
            Err(eyre::eyre!(
                "Error while executing the FindInterfaces gRPC call: {}",
                err.to_string()
            ))
        }
    }
}

fn take_single<T>(mut items: Vec<T>) -> Result<T, eyre::Error> {
    let len = items.len();
    if len != 1 {
        return Err(eyre::eyre!("expected exactly 1 element, found {len}"));
    }
    Ok(items.remove(0))
}

pub async fn get_host_machine_id(
    fetcher: &PeriodicConfigFetcher,
    forge_client_config: Arc<ForgeClientConfig>,
    forge_api: &str,
) -> Result<Option<MachineId>, eyre::Error> {
    if let Some(interface_id) = fetcher.get_host_machine_interface_id() {
        let mut client = create_forge_client(forge_api, &forge_client_config).await?;
        let interface_list = get_interface_list(&mut client, MachineInterfaceId::from_str(&interface_id)?)
            .await
            .map_err(|e| {
                tracing::error!("get_interface({}) failed: {:?}", interface_id, e);
                e
            })?;
        let interface = take_single(interface_list.interfaces)?;
        if let Some(id) = interface.machine_id {
            return Ok(Some(id));
        }
    }

    Ok(None)
}

pub async fn get_host_machine_id_retry(
    fetcher: &PeriodicConfigFetcher,
    forge_client_config: Arc<ForgeClientConfig>,
    forge_api: &str,
) -> Result<MachineId, eyre::Report> {
    let retry_policy = ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(100))
        .with_max_delay(Duration::from_secs(10))
        .with_factor(2.0)
        .with_total_delay(Some(Duration::from_secs(10)));

    (|| async {
        get_host_machine_id(
            fetcher,
            forge_client_config.clone(),
            forge_api,
        )
        .await
        .map_err(|e| {
            tracing::warn!("get_host_machine_id() failed: {:?}", e);
            e
        })?
        .ok_or(eyre::eyre!("get_host_machine_id() got no value"))
    })
    .retry(retry_policy)
    .await
}
