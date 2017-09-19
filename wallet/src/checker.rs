// Copyright 2016 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Utilities to check the status of all the outputs we have stored in
//! the wallet storage and update them.

use api;
use core::core::transaction;
use core::consensus;

use secp::{self, pedersen};
use util;

use extkey::ExtendedKey;
use types::{WalletConfig, OutputStatus, WalletData};

/// Goes through the list of outputs that haven't been spent yet and check
/// with a node whether their status has changed.
pub fn refresh_outputs(config: &WalletConfig, ext_key: &ExtendedKey) {
	let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);

	match get_tip(config) {
		Ok(tip) => {
			// operate within a lock on wallet data
			let _ = WalletData::with_wallet(&config.data_file_dir, |wallet_data| {
				// check each output that's not spent
				for out in &mut wallet_data.outputs {
					println!("checking an output");
					if out.status != OutputStatus::Spent {
						// figure out the commitment
						let key = ext_key.derive(&secp, out.n_child).unwrap();
						let commitment = secp.commit(out.value, key.key).unwrap();

						// TODO check the pool for unconfirmed

						let out_res = get_output_by_commitment(config, commitment);

						match out_res {
							Ok(utxo) => {
								// output is known, it's a new utxo
								if utxo.features.contains(transaction::COINBASE_OUTPUT) {
									println!("coinbase *** {}, {}, {}", utxo.height, tip.height, consensus::COINBASE_MATURITY);
									let is_mature = tip.height >= (utxo.height + consensus::COINBASE_MATURITY);
									if is_mature {
										out.status = OutputStatus::Unspent;
									} else {
										out.status = OutputStatus::Immature;
									}
								} else {
									out.status = OutputStatus::Unspent;
								}
								out.height = utxo.height;
							},
							Err(api::Error::NotFound) => {
								if out.status == OutputStatus::Unspent {
									out.status = OutputStatus::Spent;
								}
							},
							Err(_) => {
								//TODO find error with connection and return
								//error!("Error contacting server node at {}. Is it running?", config.check_node_api_http_addr);
							}
						}
					}
				}
			});
		},
		Err(_) => {}
	}
}

fn get_tip(config: &WalletConfig) -> Result<api::Tip, api::Error> {
	let url = format!("{}/v1/chain", config.check_node_api_http_addr);
	api::client::get::<api::Tip>(url.as_str())
}

// queries a reachable node for a given output, checking whether it's been
// confirmed
fn get_output_by_commitment(config: &WalletConfig,
                            commit: pedersen::Commitment)
                            -> Result<api::Utxo, api::Error> {
	let url = format!("{}/v1/chain/utxo/{}",
	                  config.check_node_api_http_addr,
	                  util::to_hex(commit.as_ref().to_vec()));
	api::client::get::<api::Utxo>(url.as_str())
}
