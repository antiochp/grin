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

//! Header only extension - to apply headers to header MMR during header sync.

use croaring::Bitmap;

use core::core::hash::Hashed;
use core::core::pmmr::{self, PMMR};
use core::core::{Block, BlockHeader, Input, Output, OutputIdentifier, Transaction};
use error::{Error, ErrorKind};
use grin_store::pmmr_db_backend::PMMRDBBackend;
use store::Batch;
use txhashset::TxHashSet;
use util::LOGGER;

pub struct HeaderExtension<'a> {
	header: BlockHeader,
	pmmr: PMMR<'a, BlockHeader, PMMRDBBackend<BlockHeader>>,
	pub batch: &'a Batch<'a>,
	pub rollback: bool,
}

impl<'a> HeaderExtension<'a> {
	pub fn new(trees: &'a mut TxHashSet, batch: &'a Batch, header: BlockHeader) -> HeaderExtension<'a> {
		HeaderExtension {
			header,
			pmmr: PMMR::at(
				&mut trees.header_pmmr_h.backend,
				trees.header_pmmr_h.last_pos,
			),
			rollback: false,
			batch,
		}
	}

	pub fn apply_header(&mut self, header: &BlockHeader) -> Result<(), Error> {
		let pos = self.pmmr
			.push(header.clone())
			.map_err(&ErrorKind::TxHashSetErr)?;

			debug!(
				LOGGER,
				"header_extension: apply_header: header {} at {}, MMR pos {}",
				header.hash(),
				header.height,
				pos,
			);

		// Update the header on the extension to reflect the block we just applied.
		self.header = header.clone();

		Ok(())
	}

	/// Force the rollback of this extension, no matter the result.
	pub fn force_rollback(&mut self) {
		self.rollback = true;
	}

	pub fn rewind(&mut self, header: &BlockHeader) -> Result<(), Error> {
		let pos = pmmr::insertion_to_pmmr_index(header.height);

		debug!(
			LOGGER,
			"header_extension: rewind: {} at {}, pos {}",
			header.hash(),
			header.height,
			pos
		);

		self.pmmr
			.rewind(pos, &Bitmap::create())
			.map_err(&ErrorKind::TxHashSetErr)?;

		// Update our header to reflect the one we rewound to.
		self.header = header.clone();

		Ok(())
	}

	pub fn size(&self) -> u64 {
		self.pmmr.unpruned_size()
	}
}
