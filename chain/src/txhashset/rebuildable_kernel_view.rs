// Copyright 2019 The Grin Developers
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

//! Lightweight rebuildable view of the kernel MMR.
//! Used when receiving a "kernel data" file from a peer to
//! (re)build the kernel MMR locally.

use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use croaring::Bitmap;
use tempfile;
use tempfile::TempDir;

use crate::core::core::hash::Hashed;
use crate::core::core::pmmr::{self, ReadonlyPMMR, PMMR};
use crate::core::core::{BlockHeader, TxKernel, TxKernelEntry};
use crate::core::ser::{Readable, StreamingReader};
use crate::error::{Error, ErrorKind};
use crate::store::Batch;
use crate::txhashset::txhashset::{PMMRHandle, TxHashSet};
use grin_store::pmmr::PMMRBackend;

/// A "rebuildable" kernel view.
/// Note: We have a reference to an existing txhashset.
/// We use this existing txhashset to access an existing set of headers.
/// We do not write to this existing txhashset, only to the backend of this kernel view.
///
pub struct RebuildableKernelView<'a> {
	kernel_pmmr: PMMR<'a, TxKernel, PMMRBackend<TxKernel>>,
	header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
	batch: &'a Batch<'a>,
	path: &'a Path,
}

impl<'a> RebuildableKernelView<'a> {
	pub fn new(
		kernel_pmmr: PMMR<'a, TxKernel, PMMRBackend<TxKernel>>,
		header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
		batch: &'a Batch<'_>,
		path: &'a Path,
	) -> RebuildableKernelView<'a> {
		RebuildableKernelView {
			kernel_pmmr,
			header_pmmr,
			batch,
			path,
		}
	}

	fn truncate(&mut self) -> Result<(), Error> {
		debug!("Truncating temp kernel view.");
		self.kernel_pmmr
			.rewind(0, &Bitmap::create())
			.map_err(&ErrorKind::TxHashSetErr)?;
		Ok(())
	}

	fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, Error> {
		let pos = pmmr::insertion_to_pmmr_index(height + 1);
		if let Some(entry) = self.header_pmmr.get_data(pos) {
			self.batch
				.get_block_header(&entry.hash())
				.map_err(|e| ErrorKind::StoreErr(e, "get_block_header".to_owned()).into())
		} else {
			return Err(ErrorKind::TxHashSetErr("get_data".to_owned()).into());
		}
	}

	/// TODO - Cleaner to move this to backend?
	pub fn copy_to_txhashset(&self, txhashset_path: PathBuf) -> Result<(), Error> {
		let to_kernel_path = txhashset_path.join("kernel");
		for file in &["pmmr_data.bin", "pmmr_hash.bin", "pmmr_size.bin"] {
			fs::copy(self.path.join(file), to_kernel_path.join(file))?;
		}
		Ok(())
	}

	pub fn rebuild(&mut self, data: &mut Read, header: &BlockHeader) -> Result<(), Error> {
		// Rebuild is all-or-nothing. Truncate everything before we begin.
		self.truncate()?;

		let mut stream = StreamingReader::new(data, Duration::from_secs(1));

		let mut current_pos = 0;
		let mut current_header = self.get_header_by_height(0)?;
		loop {
			while current_pos < current_header.kernel_mmr_size {
				// Read and verify the next kernel from the stream of data.
				let kernel: TxKernel = TxKernelEntry::read(&mut stream)?.into();
				kernel.verify()?;

				// Apply it to the MMR and keep track of last_pos.
				let (_, last_pos) = self.apply_kernel(&kernel)?;
				current_pos = last_pos;
			}

			// Validate the kernel MMR root against the current header.
			self.validate_root(&current_header)?;

			// Periodically sync the PMMR backend as we rebuild it.
			if current_header.height % 1000 == 0 {
				self.kernel_pmmr
					.sync()
					.map_err(|_| ErrorKind::TxHashSetErr("failed to sync pmmr".into()))?;
				debug!(
					"Rebuilt to header height: {}, kernels: {} (MMR size: {}) ...",
					current_header.height,
					pmmr::n_leaves(self.kernel_pmmr.last_pos),
					self.kernel_pmmr.last_pos,
				);
			}

			// Done if we have reached the specified header.
			if current_header == *header {
				break;
			} else if current_header.height >= header.height {
				return Err(ErrorKind::InvalidTxHashSet(format!(
					"Header mismatch when rebuilding kernel MMR.",
				))
				.into());
			} else {
				current_header = self.get_header_by_height(current_header.height + 1)?;
			}
		}

		// One final sync to ensure everything is saved to tempdir.
		self.kernel_pmmr
			.sync()
			.map_err(|_| ErrorKind::TxHashSetErr("failed to sync pmmr".into()))?;

		debug!(
			"Kernel MMR rebuilt, header height: {}, kernels: {} (MMR size: {})",
			current_header.height,
			pmmr::n_leaves(self.kernel_pmmr.last_pos),
			self.kernel_pmmr.last_pos,
		);

		Ok(())
	}

	fn validate_root(&self, header: &BlockHeader) -> Result<(), Error> {
		let root = self.kernel_pmmr.root();
		if root != header.kernel_root {
			return Err(ErrorKind::InvalidTxHashSet(format!(
				"Kernel root for header {} (height: {}) does not match.",
				header.hash(),
				header.height,
			))
			.into());
		}
		Ok(())
	}

	/// Push kernel onto MMR (hash, data and size files).
	/// Returns the pos of the element applies and "last_pos" including all new parents.
	pub fn apply_kernel(&mut self, kernel: &TxKernel) -> Result<(u64, u64), Error> {
		let pos = self
			.kernel_pmmr
			.push(kernel)
			.map_err(&ErrorKind::TxHashSetErr)?;
		Ok(pos)
	}
}
