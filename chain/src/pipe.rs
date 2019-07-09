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

//! Implementation of the chain block acceptance (or refusal) pipeline.

use crate::chain::OrphanBlockPool;
use crate::core::consensus;
use crate::core::core::hash::Hash;
use crate::core::core::hash::Hashed;
use crate::core::core::verifier_cache::VerifierCache;
use crate::core::core::Committed;
use crate::core::core::{Block, BlockHeader, BlockSums};
use crate::core::global;
use crate::core::pow;
use crate::error::{Error, ErrorKind};
use crate::store;
use crate::txhashset;
use crate::types::{Options, Tip};
use crate::util::RwLock;
use chrono::prelude::Utc;
use chrono::Duration;
use grin_store;
use std::sync::Arc;

/// Contextual information required to process a new block and either reject or
/// accept it.
pub struct BlockContext<'a> {
	/// The options
	pub opts: Options,
	/// The pow verifier to use when processing a block.
	pub pow_verifier: fn(&BlockHeader) -> Result<(), pow::Error>,
	/// The active txhashset (rewindable MMRs) to use for block processing.
	pub txhashset: &'a mut txhashset::TxHashSet,
	/// The active batch to use for block processing.
	pub batch: store::Batch<'a>,
	/// The verifier cache (caching verifier for rangeproofs and kernel signatures)
	pub verifier_cache: Arc<RwLock<dyn VerifierCache>>,
	/// Recent orphan blocks to avoid double-processing
	pub orphans: Arc<OrphanBlockPool>,
}

// Check if we already know about this block for various reasons
// from cheapest to most expensive (delay hitting the db until last).
fn check_known(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	check_known_head(header, ctx)?;
	check_known_orphans(header, ctx)?;
	check_known_store(header, ctx)?;
	Ok(())
}

fn head(ctx: &BlockContext<'_>) -> Result<Tip, Error> {
	ctx.txhashset.get_confirmed_head()
}

/// Runs the block processing pipeline, including validation and finding a
/// place for the new block in the chain.
/// Returns new head if chain head updated.
pub fn process_block(b: &Block, ctx: &mut BlockContext<'_>) -> Result<Option<Tip>, Error> {
	debug!(
		"pipe: process_block {} at {} [in/out/kern: {}/{}/{}]",
		b.hash(),
		b.header.height,
		b.inputs().len(),
		b.outputs().len(),
		b.kernels().len(),
	);

	// Check if we have already processed this block previously.
	check_known(&b.header, ctx)?;

	let head = head(ctx)?;

	let is_next = b.header.prev_hash == head.last_block_h;

	// Block is an orphan if we do not know about the previous full block.
	// Skip this check if we have just processed the previous block
	// or the full txhashset state (fast sync) at the previous block height.
	let prev = prev_header_store(&b.header, &mut ctx.batch)?;
	if !is_next && !ctx.batch.block_exists(&prev.hash())? {
		return Err(ErrorKind::Orphan.into());
	}

	// Process the header for the block.
	// Note: We still want to process the full block if we have seen this header before
	// as we may have processed it "header first" and not yet processed the full block.
	process_block_header(&b.header, ctx)?;

	// Validate the block itself, make sure it is internally consistent.
	// Use the verifier_cache for verifying rangeproofs and kernel signatures.
	validate_block(b, ctx)?;

	// Add the block the db. This will be committed if processing is successful
	// even if the extension is rolled back (chain is not extended, block is on a fork).
	add_block(b, &ctx.batch)?;

	// Start a chain extension unit of work dependent on the success of the
	// internal validation and saving operations
	let block_sums = txhashset::extending(&mut ctx.txhashset, &mut ctx.batch, |extension| {
		let block_sums = rewind_and_apply_block(&b.header, extension)?;

		// If applying this block does not increase the work on the chain then
		// we know we have not yet updated the chain to produce a new chain head.
		if !has_more_work(&b.header, &head) {
			extension.force_rollback();
		}

		Ok(block_sums)
	})?;

	// Add the validated block to the db along with the corresponding block_sums.
	// We do this even if we have not increased the total cumulative work
	// so we can maintain multiple (in progress) forks.
	add_block_sums(&b.hash(), &block_sums, &ctx.batch)?;

	// If we have no "tail" then set it now.
	if ctx.batch.tail().is_err() {
		update_body_tail(&b.header, &ctx.batch)?;
	}

	// TODO - Consider cleaning this up?
	if has_more_work(&b.header, &head) {
		Ok(Some(Tip::from_header(&b.header)))
	} else {
		Ok(None)
	}
}

/// Sync a chunk of block headers.
/// This is only used during header sync.
pub fn sync_block_headers(
	headers: &[BlockHeader],
	ctx: &mut BlockContext<'_>,
) -> Result<(), Error> {
	if headers.is_empty() {
		return Ok(());
	}

	let first_header = headers.first().expect("first header");
	let last_header = headers.last().expect("last header");
	let prev_header = ctx.batch.get_previous_header(&first_header)?;
	let last_known = ctx.batch.get_block_header(&last_header.hash()).is_ok();

	// Add all headers in the chunk to the db and validate each one (based on previous now in db).
	// Note: The db batch will only be committed for the whole chunk if the entire chunk
	// is processed successfully.
	for header in headers {
		add_block_header(header, &ctx.batch)?;
		validate_header(header, ctx)?;
	}

	let mut pmmr = ctx.txhashset.sync_head_pmmr_mut();
	txhashset::header_extending(&mut pmmr, &mut ctx.batch, |extension| {
		// We are done if headers are all known and would not extend the current MMR.
		let head = extension.get_confirmed_head()?;
		if last_known {
			if !has_more_work(&last_header, &head) {
				return Ok(());
			}
		}

		// All headers in the chunk are already in the db so simply process
		// the last header as if it were a fork.
		rewind_and_apply_header(&last_header, extension)?;

		Ok(())
	})?;

	Ok(())
}

/// Process a block header. Update the header MMR and corresponding header_head if this header
/// increases the total work relative to header_head.
/// Note: In contrast to processing a full block we treat "already known" as success
/// to allow processing to continue (for header itself).
pub fn process_block_header(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	// Check this header is not an orphan, we must know about the previous header to continue.
	let prev_header = ctx.batch.get_previous_header(&header)?;

	// Check if we already know about the full block for this header.
	// If we have seen this full block before then we should refuse the header.
	check_known(header, ctx)?;

	let header_known = ctx.batch.get_block_header(&header.hash()).is_ok();

	// Validate the header and add to our db.
	// If this header was successfully processed on a losing fork (extension rollback)
	// we still want to add the header to our db.
	validate_header(header, ctx)?;
	add_block_header(header, &ctx.batch)?;

	let mut pmmr = ctx.txhashset.header_head_pmmr_mut();
	txhashset::header_extending(&mut pmmr, &mut ctx.batch, |extension| {
		let head = extension.get_confirmed_head()?;
		if header_known {
			if !has_more_work(header, &head) {
				return Ok(());
			}
		}

		// Header is in the db so simply process it.
		rewind_and_apply_header(header, extension)?;

		// Rollback the MMR unless we have increased the total work.
		if !has_more_work(&header, &head) {
			extension.force_rollback();
		}
		Ok(())
	})?;

	Ok(())
}

/// Quick in-memory check to fast-reject any block handled recently.
/// Keeps duplicates from the network in check.
/// Checks against the last_block_h and prev_block_h of the chain head.
fn check_known_head(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	let head = head(ctx)?;
	let bh = header.hash();
	if bh == head.last_block_h || bh == head.prev_block_h {
		return Err(ErrorKind::Unfit("already known in head".to_string()).into());
	}
	Ok(())
}

/// Check if this block is in the set of known orphans.
fn check_known_orphans(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	if ctx.orphans.contains(&header.hash()) {
		Err(ErrorKind::Unfit("already known in orphans".to_string()).into())
	} else {
		Ok(())
	}
}

// Check if this block is in the store already.
fn check_known_store(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	match ctx.batch.block_exists(&header.hash()) {
		Ok(true) => {
			let head = head(ctx)?;
			if header.height < head.height.saturating_sub(50) {
				// TODO - we flag this as an "abusive peer" but only in the case
				// where we have the full block in our store.
				// So this is not a particularly exhaustive check.
				Err(ErrorKind::OldBlock.into())
			} else {
				Err(ErrorKind::Unfit("already known in store".to_string()).into())
			}
		}
		Ok(false) => {
			// Not yet processed this block, we can proceed.
			Ok(())
		}
		Err(e) => {
			return Err(ErrorKind::StoreErr(e, "pipe get this block".to_owned()).into());
		}
	}
}

// Find the previous header from the store.
// Return an Orphan error if we cannot find the previous header.
fn prev_header_store(
	header: &BlockHeader,
	batch: &mut store::Batch<'_>,
) -> Result<BlockHeader, Error> {
	let prev = batch.get_previous_header(&header).map_err(|e| match e {
		grin_store::Error::NotFoundErr(_) => ErrorKind::Orphan,
		_ => ErrorKind::StoreErr(e, "check prev header".into()),
	})?;
	Ok(prev)
}

/// First level of block validation that only needs to act on the block header
/// to make it as cheap as possible. The different validations are also
/// arranged by order of cost to have as little DoS surface as possible.
fn validate_header(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	// check version, enforces scheduled hard fork
	if !consensus::valid_header_version(header.height, header.version) {
		error!(
			"Invalid block header version received ({:?}), maybe update Grin?",
			header.version
		);
		return Err(ErrorKind::InvalidBlockVersion(header.version).into());
	}

	// TODO: remove CI check from here somehow
	if header.timestamp > Utc::now() + Duration::seconds(12 * (consensus::BLOCK_TIME_SEC as i64))
		&& !global::is_automated_testing_mode()
	{
		// refuse blocks more than 12 blocks intervals in future (as in bitcoin)
		// TODO add warning in p2p code if local time is too different from peers
		return Err(ErrorKind::InvalidBlockTime.into());
	}

	if !ctx.opts.contains(Options::SKIP_POW) {
		if !header.pow.is_primary() && !header.pow.is_secondary() {
			return Err(ErrorKind::LowEdgebits.into());
		}
		let edge_bits = header.pow.edge_bits();
		if !(ctx.pow_verifier)(header).is_ok() {
			error!(
				"pipe: error validating header with cuckoo edge_bits {}",
				edge_bits
			);
			return Err(ErrorKind::InvalidPow.into());
		}
	}

	// First I/O cost, delayed as late as possible.
	let prev = prev_header_store(header, &mut ctx.batch)?;

	// make sure this header has a height exactly one higher than the previous
	// header
	if header.height != prev.height + 1 {
		return Err(ErrorKind::InvalidBlockHeight.into());
	}

	// TODO - get rid of the automated testing mode check here somehow
	if header.timestamp <= prev.timestamp && !global::is_automated_testing_mode() {
		// prevent time warp attacks and some timestamp manipulations by forcing strict
		// time progression (but not in CI mode)
		return Err(ErrorKind::InvalidBlockTime.into());
	}

	// verify the proof of work and related parameters
	// at this point we have a previous block header
	// we know the height increased by one
	// so now we can check the total_difficulty increase is also valid
	// check the pow hash shows a difficulty at least as large
	// as the target difficulty
	if !ctx.opts.contains(Options::SKIP_POW) {
		if header.total_difficulty() <= prev.total_difficulty() {
			return Err(ErrorKind::DifficultyTooLow.into());
		}

		let target_difficulty = header.total_difficulty() - prev.total_difficulty();

		if header.pow.to_difficulty(header.height) < target_difficulty {
			return Err(ErrorKind::DifficultyTooLow.into());
		}

		// explicit check to ensure total_difficulty has increased by exactly
		// the _network_ difficulty of the previous block
		// (during testnet1 we use _block_ difficulty here)
		let child_batch = ctx.batch.child()?;
		let diff_iter = store::DifficultyIter::from_batch(prev.hash(), child_batch);
		let next_header_info = consensus::next_difficulty(header.height, diff_iter);
		if target_difficulty != next_header_info.difficulty {
			info!(
				"validate_header: header target difficulty {} != {}",
				target_difficulty.to_num(),
				next_header_info.difficulty.to_num()
			);
			return Err(ErrorKind::WrongTotalDifficulty.into());
		}
		// check the secondary PoW scaling factor if applicable
		if header.pow.secondary_scaling != next_header_info.secondary_scaling {
			info!(
				"validate_header: header secondary scaling {} != {}",
				header.pow.secondary_scaling, next_header_info.secondary_scaling
			);
			return Err(ErrorKind::InvalidScaling.into());
		}
	}

	Ok(())
}

fn validate_block(block: &Block, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	let prev = ctx.batch.get_previous_header(&block.header)?;
	block
		.validate(&prev.total_kernel_offset, ctx.verifier_cache.clone())
		.map_err(|e| ErrorKind::InvalidBlockProof(e))?;
	Ok(())
}

/// Verify the block is not spending coinbase outputs before they have sufficiently matured.
fn verify_coinbase_maturity(block: &Block, ext: &txhashset::Extension<'_>) -> Result<(), Error> {
	ext.utxo_view()
		.verify_coinbase_maturity(&block.inputs(), block.header.height)
}

/// Verify kernel sums across the full utxo and kernel sets based on block_sums
/// of previous block accounting for the inputs|outputs|kernels of the new block.
fn verify_block_sums(b: &Block, batch: &store::Batch<'_>) -> Result<BlockSums, Error> {
	// TODO - this is 2 db calls, can we optimize this?
	// Retrieve the block_sums for the previous block.
	let prev = batch.get_previous_header(&b.header)?;
	let block_sums = batch.get_block_sums(&prev.hash())?;

	// Overage is based purely on the new block.
	// Previous block_sums have taken all previous overage into account.
	let overage = b.header.overage();

	// Offset on the other hand is the total kernel offset from the new block.
	let offset = b.header.total_kernel_offset();

	// Verify the kernel sums for the block_sums with the new block applied.
	let (utxo_sum, kernel_sum) =
		(block_sums, b as &dyn Committed).verify_kernel_sums(overage, offset)?;

	Ok(BlockSums {
		utxo_sum,
		kernel_sum,
	})
}

/// Officially adds the block to our chain.
/// Header must be added separately (assume this has been done previously).
fn add_block(b: &Block, batch: &store::Batch<'_>) -> Result<(), Error> {
	batch
		.save_block(b)
		.map_err(|e| ErrorKind::StoreErr(e, "pipe save block".to_owned()))?;
	Ok(())
}

fn add_block_sums(
	bh: &Hash,
	block_sums: &BlockSums,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	batch.save_block_sums(bh, block_sums)?;
	Ok(())
}

/// Update the block chain tail so we can know the exact tail of full blocks in this node
fn update_body_tail(bh: &BlockHeader, batch: &store::Batch<'_>) -> Result<(), Error> {
	let tip = Tip::from_header(bh);
	batch
		.save_body_tail(&tip)
		.map_err(|e| ErrorKind::StoreErr(e, "pipe save body tail".to_owned()))?;
	debug!("body tail {} @ {}", bh.hash(), bh.height);
	Ok(())
}

/// Officially adds the block header to our header chain.
fn add_block_header(bh: &BlockHeader, batch: &store::Batch<'_>) -> Result<(), Error> {
	batch
		.save_block_header(bh)
		.map_err(|e| ErrorKind::StoreErr(e, "pipe save header".to_owned()))?;
	Ok(())
}

// Whether the provided block totals more work than the chain tip
fn has_more_work(header: &BlockHeader, head: &Tip) -> bool {
	header.total_difficulty() > head.total_difficulty
}

/// Rewind the header chain and (re)apply headers up to and including the provided header.
///
/// TODO - "fork_hashes" here grows with the size of the chain - consider batching up somehow?
///
pub fn rewind_and_apply_header(
	header: &BlockHeader,
	ext: &mut txhashset::HeaderExtension<'_>,
) -> Result<(), Error> {
	let mut fork_hashes = vec![];
	let mut current = header.clone();
	while current.height > 0 && !ext.is_on_current_chain(&current).is_ok() {
		fork_hashes.push(current.hash());
		current = ext.batch.get_previous_header(&current)?;
	}
	fork_hashes.reverse();

	// Rewind the txhashset state back to the block where we forked from the most work chain.
	ext.rewind(&current)?;

	// Re-apply all headers on this fork.
	for h in fork_hashes {
		let header = ext.batch.get_block_header(&h)?;

		// TODO - Pull this out into a single fn.
		{
			ext.validate_root(&header)?;
			ext.apply_header(&header)?;
		}
	}

	Ok(())
}

/// Rewind and (re)apply all necessary blocks up to and including the block for the provided header.
///
/// TODO - "fork_hashes" here grows with the size of the chain - consider batching up somehow?
///
pub fn rewind_and_apply_block(
	header: &BlockHeader,
	ext: &mut txhashset::Extension<'_>,
) -> Result<BlockSums, Error> {
	let mut fork_hashes = vec![];
	let mut current = header.clone();
	while current.height > 0 && !ext.is_on_current_chain(&current).is_ok() {
		fork_hashes.push(current.hash());
		current = ext.batch.get_previous_header(&current)?;
	}
	fork_hashes.reverse();

	// Rewind the txhashset state back to the block where we forked from the most work chain.
	ext.rewind(&current)?;

	let mut block_sums = BlockSums::default();
	for h in fork_hashes {
		let block = ext.batch.get_block(&h)?;

		// TODO - Pull this out into a single fn.
		{
			verify_coinbase_maturity(&block, ext)?;
			validate_utxo(&block, ext)?;
			block_sums = verify_block_sums(&block, &ext.batch)?;

			ext.validate_header_root(&block.header)?;
			ext.apply_block(&block)?;
			ext.validate_roots()?;
			ext.validate_sizes()?;
		}
	}

	Ok(block_sums)
}

fn validate_utxo(block: &Block, ext: &txhashset::Extension<'_>) -> Result<(), Error> {
	ext.utxo_view().validate_block(block)
}
