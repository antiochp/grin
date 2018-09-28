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

use std::collections::HashSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use croaring::Bitmap;

use util::secp::pedersen::{Commitment, RangeProof};

use core::core::committed::Committed;
use core::core::hash::{Hash, Hashed};
use core::core::merkle_proof::MerkleProof;
use core::core::pmmr::{self, ReadonlyPMMR, RewindablePMMR, PMMR};
use core::core::{Block, BlockHeader, Input, Output, OutputFeatures, OutputIdentifier, TxKernel};
use core::global;
use core::ser::{PMMRIndexHashable, PMMRable};

use error::{Error, ErrorKind};
use grin_store;
use grin_store::pmmr_db_backend::PMMRDBBackend;
use grin_store::types::prune_noop;
use store::{Batch, ChainStore};
use txhashset::{RewindableKernelView, UTXOView};
use types::{TxHashSetRoots, TxHashsetWriteStatus};
use util::{file, secp_static, zip, LOGGER};

const HEADHASHSET_SUBDIR: &'static str = "headhashset";
const HEADER_SUBDIR: &'static str = "header";
const SYNC_SUBDIR: &'static str = "sync";

struct PMMRHandle<T>
where
	T: PMMRable,
{
	backend: PMMRDBBackend<T>,
	last_pos: u64,
}

impl<T> PMMRHandle<T>
where
	T: PMMRable + ::std::fmt::Debug,
{
	fn new(root_dir: String, file_name: &str) -> Result<PMMRHandle<T>, Error> {
		let path = Path::new(&root_dir)
			.join(HEADHASHSET_SUBDIR)
			.join(file_name);
		fs::create_dir_all(path.clone())?;
		let backend = PMMRDBBackend::new(path.to_str().unwrap().to_string())?;
		let last_pos = backend.unpruned_size()?;
		Ok(PMMRHandle { backend, last_pos })
	}
}

pub struct HeadHashSet {
	header_pmmr_h: PMMRHandle<BlockHeader>,
	sync_pmmr_h: PMMRHandle<BlockHeader>,

	store: Arc<ChainStore>,
}

impl HeadHashSet {
	/// Open an existing or new set of backends for the HeadHashSet.
	pub fn open(root_dir: String, store: Arc<ChainStore>) -> Result<HeadHashSet, Error> {
		Ok(HeadHashSet {
			header_pmmr_h: PMMRHandle::new(root_dir.clone(), HEADER_SUBDIR)?,
			sync_pmmr_h: PMMRHandle::new(root_dir.clone(), SYNC_SUBDIR)?,
			store,
		})
	}
}

pub fn header_extending<'a, F, T>(
	trees: &'a mut HeadHashSet,
	batch: &'a mut Batch,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut Extension) -> Result<T, Error>,
{
	extending(&mut trees.header_pmmr_h, batch, inner)
}

pub fn sync_extending<'a, F, T>(
	trees: &'a mut HeadHashSet,
	batch: &'a mut Batch,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut Extension) -> Result<T, Error>,
{
	extending(&mut trees.sync_pmmr_h, batch, inner)
}

fn extending<'a, F, T>(
	pmmr_h: &'a mut PMMRHandle<BlockHeader>,
	batch: &'a mut Batch,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut Extension) -> Result<T, Error>,
{
	let size: u64;
	let res: Result<T, Error>;
	let rollback: bool;

	// We want to use the current head of the most work chain unless
	// we explicitly rewind the extension.
	let header = batch.head_header()?;

	// create a child transaction so if the state is rolled back by itself, all
	// index saving can be undone
	let child_batch = batch.child()?;
	{
		debug!(LOGGER, "Starting new headhashset extension.");

		let pmmr = PMMR::at(&mut pmmr_h.backend, pmmr_h.last_pos);

		let mut extension = Extension::new(pmmr, &child_batch, header);
		res = inner(&mut extension);

		rollback = extension.rollback;
		size = extension.size();
	}

	match res {
		Err(e) => {
			debug!(
				LOGGER,
				"Error returned, discarding headhashset extension: {}", e
			);
			pmmr_h.backend.discard();
			Err(e)
		}
		Ok(r) => {
			if rollback {
				debug!(LOGGER, "Rollbacking headhashset extension. size {:?}", size);
				pmmr_h.backend.discard();
			} else {
				debug!(LOGGER, "Committing headhashset extension. size {:?}", size);
				child_batch.commit()?;
				pmmr_h.backend.sync()?;
				pmmr_h.last_pos = size;
			}
			Ok(r)
		}
	}
}

pub struct Extension<'a> {
	header: BlockHeader,

	pmmr: PMMR<'a, BlockHeader, PMMRDBBackend<BlockHeader>>,

	/// Rollback flag.
	rollback: bool,

	/// Batch in which the extension occurs, public so it can be used within
	/// an `extending` closure. Just be careful using it that way as it will
	/// get rolled back with the extension (i.e on a losing fork).
	batch: &'a Batch<'a>,
}

impl<'a> Extension<'a> {
	fn new(
		pmmr: PMMR<'a, BlockHeader, PMMRDBBackend<BlockHeader>>,
		batch: &'a Batch,
		header: BlockHeader,
	) -> Extension<'a> {
		Extension {
			header,
			pmmr,
			rollback: false,
			batch,
		}
	}

	pub fn rewind(&mut self, header: &BlockHeader) -> Result<(), Error> {
		debug!(
			LOGGER,
			"Rewind headhashet extension to header {} @ {}",
			header.height,
			header.hash(),
		);

		let rewind_pos = pmmr::insertion_to_pmmr_index(header.height);

		self.pmmr
			.rewind(rewind_pos, &Bitmap::create())
			.map_err(&ErrorKind::TxHashSetErr)?;

		// Update our header to reflect the one we rewound to.
		self.header = header.clone();

		Ok(())
	}

	pub fn size(&self) -> u64 {
		self.pmmr.unpruned_size()
	}

	// Push header into the PMMR for this extension (either header or sync PMMR).
	fn apply_header(&mut self, header: &BlockHeader) -> Result<(), Error> {
		self.pmmr
			.push(header.clone())
			.map_err(&ErrorKind::TxHashSetErr)?;

		Ok(())
	}
}
