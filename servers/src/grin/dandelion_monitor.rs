// Copyright 2018 The Grin Developers
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

use rand;
use rand::Rng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use time::now_utc;

use core::core::hash::Hashed;
use core::core::transaction;
use pool::{BlockChain, PoolConfig, PoolEntryState, TransactionPool, TxSource};
use util::LOGGER;

/// A process to monitor transactions in the stempool.
/// With Dandelion, transaction can be broadcasted in stem or fluff phase.
/// When sent in stem phase, the transaction is relayed to only node: the
/// dandelion relay. In order to maintain reliability a timer is started for
/// each transaction sent in stem phase. This function will monitor the
/// stempool and test if the timer is expired for each transaction. In that case
/// the transaction will be sent in fluff phase (to multiple peers) instead of
/// sending only to the peer relay.
pub fn monitor_transactions<T>(
	config: PoolConfig,
	tx_pool: Arc<RwLock<TransactionPool<T>>>,
	stop: Arc<AtomicBool>,
) where
	T: BlockChain + Send + Sync + 'static,
{
	debug!(LOGGER, "Started Dandelion transaction monitor.");

	let _ = thread::Builder::new()
		.name("dandelion".to_string())
		.spawn(move || {
			loop {
				// this is the patience timer, we loop every n secs.
				let patience_secs = 10;
				thread::sleep(Duration::from_secs(patience_secs));

				let tx_pool = tx_pool.clone();

				// Step 1: find all "ToStem" entries in stempool from last run.
				// Aggregate them up to give a single (valid) aggregated tx and propagate it
				// to the next Dandelion relay along the stem.
				{
					let mut tx_pool = tx_pool.write().unwrap();

					let txpool_tx = tx_pool
						.txpool
						.aggregate_transaction()
						.expect("Failed to aggregate txpool txs.");
					let stem_txs = tx_pool
						.stempool
						.select_valid_transactions(
							PoolEntryState::ToStem,
							PoolEntryState::Stemmed,
							Some(&txpool_tx),
						)
						.expect("Failed to select some valid txs.");

					if stem_txs.len() > 0 {
						debug!(
							LOGGER,
							"dand_mon: Found {} txs for stemming.",
							stem_txs.len()
						);

						let agg_tx = transaction::aggregate(stem_txs)
							.expect("Failed to aggregate stempool txs.");

						let res = tx_pool.adapter.stem_tx_accepted(&agg_tx);
						if res.is_err() {
							debug!(
								LOGGER,
								"Unable to propagate stem tx. No relay? Fluffing instead."
							);

							let src = TxSource {
								debug_name: "fluff".to_string(),
								identifier: "?.?.?.?".to_string(),
							};

							let res = tx_pool.add_to_pool(src, agg_tx, false);
							if res.is_err() {
								error!(LOGGER, "Failed to add fluffed tx to txpool.");
							}
						}
					}
				}

				// Step 2: find all "ToFluff" entries in stempool from last run.
				// Aggregate them up to give a single (valid) aggregated tx and (re)add it
				// to our pool with stem=false (which will then broadcast it).
				{
					let mut tx_pool = tx_pool.write().unwrap();

					let txpool_tx = tx_pool
						.txpool
						.aggregate_transaction()
						.expect("Failed to aggregate txpool txs.");
					let stem_txs = tx_pool
						.stempool
						.select_valid_transactions(
							PoolEntryState::ToFluff,
							PoolEntryState::Fluffed,
							Some(&txpool_tx),
						)
						.expect("Failed to select some valid txs.");

					if stem_txs.len() > 0 {
						debug!(
							LOGGER,
							"dand_mon: Found {} txs for fluffing.",
							stem_txs.len()
						);

						let agg_tx = transaction::aggregate(stem_txs)
							.expect("Failed to aggregate stempool txs.");

						let src = TxSource {
							debug_name: "fluff".to_string(),
							identifier: "?.?.?.?".to_string(),
						};

						let res = tx_pool.add_to_pool(src, agg_tx, false);
						if res.is_err() {
							error!(LOGGER, "Failed to add fluffed tx to txpool.");
						}
					}
				}

				// Step 3: now find all "Fresh" entries in stempool since last run.
				// Coin flip for each (90/10) and label them as either "ToStem" or "ToFluff".
				// We will process these in the next run (waiting patience secs).
				{
					let mut tx_pool = tx_pool.write().unwrap();
					let mut rng = rand::thread_rng();

					let fresh_entries = &mut tx_pool
						.stempool
						.entries
						.iter_mut()
						.filter(|x| x.state == PoolEntryState::Fresh)
						.collect::<Vec<_>>();

					if fresh_entries.len() > 0 {
						debug!(
							LOGGER,
							"dand_mon: Found {} fresh entries in stempool.",
							fresh_entries.len()
						);

						for x in &mut fresh_entries.iter_mut() {
							let random = rng.gen_range(0, 101);
							if random <= config.dandelion_probability {
								x.state = PoolEntryState::ToStem;
							} else {
								x.state = PoolEntryState::ToFluff;
							}
						}
					}
				}

				// Step 4: now find all expired entries based on embargo timer.
				{
					let now = now_utc().to_timespec().sec;
					let embargo_sec =
						config.dandelion_embargo + rand::thread_rng().gen_range(0, 31);
					let cutoff = now - embargo_sec;

					let mut expired_entries = vec![];

					{
						let tx_pool = tx_pool.read().unwrap();
						for entry in tx_pool
							.stempool
							.entries
							.iter()
							.filter(|x| x.tx_at.sec < cutoff)
						{
							debug!(
								LOGGER,
								"dand_mon: Embargo timer expired for {:?}",
								entry.tx.hash()
							);
							expired_entries.push(entry.clone());
						}
					}

					if expired_entries.len() > 0 {
						debug!(
							LOGGER,
							"dand_mon: Found {} expired txs.",
							expired_entries.len()
						);

						{
							let mut tx_pool = tx_pool.write().unwrap();
							for entry in expired_entries {
								match tx_pool.add_to_pool(entry.src, entry.tx, false) {
									Ok(_) => {
										debug!(LOGGER, "dand_mon: Fluffed expired tx successfully.")
									}
									Err(e) => debug!(LOGGER, "error - {:?}", e),
								};
							}
						}
					}
				}

				if stop.load(Ordering::Relaxed) {
					break;
				}
			}
		});
}
