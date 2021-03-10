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

//! Lightweight readonly view into output MMR for convenience.

use crate::core::core::pmmr::ReadonlyPMMR;
use crate::core::core::{Block, BlockHeader, Inputs, Output, OutputIdentifier, Transaction};
use crate::core::global;
use crate::error::{Error, ErrorKind};
use crate::store::Batch;
use crate::types::CommitPos;
use crate::util::secp::pedersen::Commitment;
use grin_store::pmmr::PMMRBackend;

/// Readonly view of the UTXO set (based on output MMR).
pub struct UTXOView<'a> {
	output_pmmr: ReadonlyPMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
}

impl<'a> UTXOView<'a> {
	/// Build a new UTXO view.
	pub fn new(
		output_pmmr: ReadonlyPMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
	) -> UTXOView<'a> {
		UTXOView { output_pmmr }
	}

	/// Validate a block against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_block(
		&self,
		block: &Block,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		for output in block.outputs() {
			self.validate_output(output, batch)?;
		}
		self.validate_inputs(&block.inputs(), batch)
	}

	/// Validate a transaction against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_tx(
		&self,
		tx: &Transaction,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		for output in tx.outputs() {
			self.validate_output(output, batch)?;
		}
		self.validate_inputs(&tx.inputs(), batch)
	}

	/// Validate the provided inputs.
	/// Returns a vec of output identifiers corresponding to outputs
	/// that would be spent by the provided inputs.
	pub fn validate_inputs(
		&self,
		inputs: &Inputs,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		match inputs {
			Inputs::CommitOnly(inputs) => {
				let outputs_spent: Result<Vec<_>, Error> = inputs
					.iter()
					.map(|input| {
						self.validate_input(input.commitment(), batch)
							.and_then(|(out, pos)| Ok((out, pos)))
					})
					.collect();
				outputs_spent
			}
			Inputs::FeaturesAndCommit(inputs) => {
				let outputs_spent: Result<Vec<_>, Error> = inputs
					.iter()
					.map(|input| {
						self.validate_input(input.commitment(), batch)
							.and_then(|(out, pos)| {
								// Unspent output found.
								// Check input matches full output identifier.
								if out == input.into() {
									Ok((out, pos))
								} else {
									error!("input mismatch: {:?}, {:?}, {:?}", out, pos, input);
									Err(ErrorKind::Other("input mismatch".into()).into())
								}
							})
					})
					.collect();
				outputs_spent
			}
		}
	}

	// Input is valid if it is spending an (unspent) output
	// that currently exists in the output MMR.
	// Note: We lookup by commitment. Caller must compare the full input as necessary.
	fn validate_input(
		&self,
		input: Commitment,
		batch: &Batch<'_>,
	) -> Result<(OutputIdentifier, CommitPos), Error> {
		let pos = batch.get_output_pos_height(&input)?;
		if let Some(pos) = pos {
			if let Some(out) = self.get_unspent_at(pos.pos, batch)? {
				if out.commitment() == input {
					return Ok((out, pos));
				} else {
					error!("input mismatch: {:?}, {:?}, {:?}", out, pos, input);
					return Err(ErrorKind::Other(
						"input mismatch (output_pos index mismatch?)".into(),
					)
					.into());
				}
			}
		}
		Err(ErrorKind::AlreadySpent(input).into())
	}

	// Output is valid if it would not result in a duplicate commitment in the output MMR.
	fn validate_output(&self, output: &Output, batch: &Batch<'_>) -> Result<(), Error> {
		if let Ok(pos) = batch.get_output_pos(&output.commitment()) {
			if let Some(out_mmr) = self.get_unspent_at(pos, batch)? {
				if out_mmr.commitment() == output.commitment() {
					return Err(ErrorKind::DuplicateCommitment(output.commitment()).into());
				}
			}
		}
		Ok(())
	}

	/// Read output identifier from the db based on pos.
	/// Note: We need to be aware of last_pos here to handle MMR truncation correctly.
	/// We ignore everything beyond the output MMR last_pos.
	fn get_unspent_at(
		&self,
		pos: u64,
		batch: &Batch<'_>,
	) -> Result<Option<OutputIdentifier>, Error> {
		// TODO - we should be leaf_set aware here for completeness.

		if pos > self.output_pmmr.last_pos {
			Ok(None)
		} else {
			Ok(batch.get_output_by_pos(pos)?)
		}
	}

	/// Retrieves an unspent output using its PMMR position
	pub fn get_unspent_output_at(&self, pos: u64, batch: &Batch<'_>) -> Result<Output, Error> {
		match self.get_unspent_at(pos, batch)? {
			Some(output_id) => match batch.get_rangeproof_by_pos(pos)? {
				Some(rproof) => Ok(output_id.into_output(rproof)),
				None => Err(ErrorKind::RangeproofNotFound.into()),
			},
			None => Err(ErrorKind::OutputNotFound.into()),
		}
	}

	/// Verify we are not attempting to spend any coinbase outputs
	/// that have not sufficiently matured.
	pub fn verify_coinbase_maturity(
		&self,
		inputs: &Inputs,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		let inputs: Vec<_> = inputs.into();

		// Lookup the outputs being spent.
		let spent: Result<Vec<_>, _> = inputs
			.iter()
			.map(|x| self.validate_input(x.commitment(), batch))
			.collect();

		// Find the max pos of any coinbase being spent.
		let pos = spent?
			.iter()
			.filter_map(|(out, pos)| {
				if out.features.is_coinbase() {
					Some(pos.pos)
				} else {
					None
				}
			})
			.max();

		if let Some(pos) = pos {
			// If we have not yet reached 1440 blocks then
			// we can fail immediately as coinbase cannot be mature.
			if height < global::coinbase_maturity() {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}

			// Find the "cutoff" pos in the output MMR based on the
			// header from 1,000 blocks ago.
			let cutoff_height = height.saturating_sub(global::coinbase_maturity());
			let cutoff_header = self.get_header_by_height(cutoff_height, batch)?;
			let cutoff_pos = cutoff_header.output_mmr_size;

			// If any output pos exceed the cutoff_pos
			// we know they have not yet sufficiently matured.
			if pos > cutoff_pos {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}
		}

		Ok(())
	}

	/// Get the header at the specified height based on the current state of the extension.
	/// This involves two db lookups:
	///   height -> hash
	///   hash -> header
	fn get_header_by_height(&self, height: u64, batch: &Batch<'_>) -> Result<BlockHeader, Error> {
		if let Some(hash) = batch.get_header_hash_by_height(height)? {
			let header = batch.get_block_header(&hash)?;
			Ok(header)
		} else {
			Err(ErrorKind::Other("get header by height".to_string()).into())
		}
	}
}
