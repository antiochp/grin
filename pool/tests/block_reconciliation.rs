// Copyright 2020 The Grin Developers
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

pub mod common;

use self::core::core::hash::Hashed;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use self::util::RwLock;
use crate::common::ChainAdapter;
use crate::common::*;
use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;
use std::sync::Arc;

#[test]
fn test_transaction_pool_block_reconciliation() {
	util::init_test_logger();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let keychain: ExtKeychain = Keychain::from_random_seed(false).unwrap();

	let db_root = "target/.block_reconciliation";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(db_root, genesis));
	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

	// Initialize a new pool with our chain adapter.
	let mut pool = init_transaction_pool(
		Arc::new(ChainAdapter {
			chain: chain.clone(),
		}),
		verifier_cache,
	);

	add_some_blocks(&chain, 3, &keychain);

	let header_1 = chain.get_header_by_height(1).unwrap();

	// Now create tx to spend an early coinbase (now matured).
	// Provides us with some useful outputs to test with.
	let initial_tx = test_transaction_spending_coinbase(&keychain, &header_1, vec![10, 20, 30, 40]);

	// Mine that initial tx so we can spend it with multiple txs.
	add_block(&chain, vec![initial_tx], &keychain);

	let header = chain.head_header().unwrap();

	// Preparation: We will introduce three root pool transactions.
	// 1. A transaction that should be invalidated because it is exactly
	//  contained in the block.
	// 2. A transaction that should be invalidated because the input is
	//  consumed in the block, although it is not exactly consumed.
	// 3. A transaction that should remain after block reconciliation.
	let block_transaction = test_transaction(&keychain, vec![10], vec![8]);
	let conflict_transaction = test_transaction(&keychain, vec![20], vec![12, 6]);
	let valid_transaction = test_transaction(&keychain, vec![30], vec![13, 15]);

	// We will also introduce a few children:
	// 4. A transaction that descends from transaction 1, that is in
	//  turn exactly contained in the block.
	let block_child = test_transaction(&keychain, vec![8], vec![5, 1]);
	// 5. A transaction that descends from transaction 4, that is not
	//  contained in the block at all and should be valid after
	//  reconciliation.
	let pool_child = test_transaction(&keychain, vec![5], vec![3]);
	// 6. A transaction that descends from transaction 2 that does not
	//  conflict with anything in the block in any way, but should be
	//  invalidated (orphaned).
	let conflict_child = test_transaction(&keychain, vec![12], vec![2]);
	// 7. A transaction that descends from transaction 2 that should be
	//  valid due to its inputs being satisfied by the block.
	let conflict_valid_child = test_transaction(&keychain, vec![6], vec![4]);
	// 8. A transaction that descends from transaction 3 that should be
	//  invalidated due to an output conflict.
	let valid_child_conflict = test_transaction(&keychain, vec![13], vec![9]);
	// 9. A transaction that descends from transaction 3 that should remain
	//  valid after reconciliation.
	let valid_child_valid = test_transaction(&keychain, vec![15], vec![11]);
	// 10. A transaction that descends from both transaction 6 and
	//  transaction 9
	let mixed_child = test_transaction(&keychain, vec![2, 11], vec![7]);

	let txs_to_add = vec![
		block_transaction,
		conflict_transaction,
		valid_transaction.clone(),
		block_child,
		pool_child.clone(),
		conflict_child,
		conflict_valid_child.clone(),
		valid_child_conflict.clone(),
		valid_child_valid.clone(),
		mixed_child,
	];

	// First we add the above transactions to the pool.
	// All should be accepted.
	assert_eq!(pool.total_size(), 0);

	for tx in &txs_to_add {
		pool.add_to_pool(test_source(), tx.clone(), false, &header)
			.unwrap();
	}

	assert_eq!(pool.total_size(), txs_to_add.len());

	// Now we prepare the block that will cause the above conditions to be met.
	// First, the transactions we want in the block:
	// - Copy of 1
	let block_tx_1 = test_transaction(&keychain, vec![10], vec![8]);
	// - Conflict w/ 2, satisfies 7
	let block_tx_2 = test_transaction(&keychain, vec![20], vec![6]);
	// - Copy of 4
	let block_tx_3 = test_transaction(&keychain, vec![8], vec![5, 1]);
	// - Output conflict w/ 8
	let block_tx_4 = test_transaction(&keychain, vec![40], vec![9, 31]);

	let block_txs = vec![block_tx_1, block_tx_2, block_tx_3, block_tx_4];
	add_block(&chain, block_txs, &keychain);
	let block = chain.get_block(&chain.head().unwrap().hash()).unwrap();

	// Check the pool still contains everything we expect at this point.
	assert_eq!(pool.total_size(), txs_to_add.len());

	// And reconcile the pool with this latest block.
	pool.reconcile_block(&block).unwrap();

	assert_eq!(pool.total_size(), 4);
	assert_eq!(pool.txpool.entries[0].tx, valid_transaction);
	assert_eq!(pool.txpool.entries[1].tx, pool_child);
	assert_eq!(pool.txpool.entries[2].tx, conflict_valid_child);
	assert_eq!(pool.txpool.entries[3].tx, valid_child_valid);

	// Cleanup db directory
	clean_output_dir(db_root.into());
}
