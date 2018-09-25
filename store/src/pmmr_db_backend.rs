// Copyright 2018 The Grin Developers
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

//! Implementation of the persistent Backend for the prunable MMR tree.

use std::{fs, io, marker};

use croaring::Bitmap;

use core::core::hash::{Hash, Hashed};
use core::core::pmmr::{self, family, Backend};
use core::core::BlockHeader;
use core::ser::{self, PMMRable};
use leaf_set::LeafSet;
use pmmr_backend::PMMR_HASH_FILE;
use prune_list::PruneList;
use types::{prune_noop, AppendOnlyFile};
use util::LOGGER;

pub struct PMMRDBBackend<T>
where
	T: PMMRable,
{
	data_dir: String,
	// prunable: bool,
	hash_file: AppendOnlyFile,
	// leaf_set: LeafSet,
	// prune_list: PruneList,
	_marker: marker::PhantomData<T>,
}

impl<T> Backend<T> for PMMRDBBackend<T>
where
	T: PMMRable + ::std::fmt::Debug,
{
	/// Append the provided Hashes to the backend storage.
	#[allow(unused_variables)]
	fn append(&mut self, position: u64, data: Vec<(Hash, Option<T>)>) -> Result<(), String> {
		for (h, _d) in data {
			self.hash_file.append(&mut ser::ser_vec(&h).unwrap());
		}
		Ok(())
	}

	fn get_from_file(&self, position: u64) -> Option<Hash> {
		// Read PMMR
		// The MMR starts at 1, our binary backend starts at 0
		let pos = position - 1;

		// Must be on disk, doing a read at the correct position
		let hash_record_len = 32;
		let file_offset = (pos as usize) * hash_record_len;
		let hash = self.hash_file.read(file_offset, hash_record_len);
		match ser::deserialize(&mut &hash[..]) {
			Ok(hash) => Some(hash),
			Err(e) => {
				error!(
					LOGGER,
					"Corrupted storage, could not read an entry from hash store: {:?}", e
				);
				return None;
			}
		}
	}

	fn get_data_from_file(&self, position: u64) -> Option<T> {
		unimplemented!()
	}

	/// Get the hash at pos.
	fn get_hash(&self, pos: u64) -> Option<(Hash)> {
		self.get_from_file(pos)
	}

	/// Get the data at pos.
	/// Return None if it has been removed or if pos is not a leaf node.
	fn get_data(&self, pos: u64) -> Option<(T)> {
		unimplemented!()
	}

	/// Rewind the PMMR backend to the given position.
	fn rewind(&mut self, position: u64, _rewind_rm_pos: &Bitmap) -> Result<(), String> {
		let record_len = 32 as u64;
		let file_pos = position * record_len;
		self.hash_file.rewind(file_pos);
		Ok(())
	}

	/// Remove by insertion position.
	fn remove(&mut self, pos: u64) -> Result<(), String> {
		unimplemented!()
	}

	/// Return data file path
	fn get_data_file_path(&self) -> String {
		unimplemented!()
	}

	fn snapshot(&self, header: &BlockHeader) -> Result<(), String> {
		unimplemented!()
	}

	fn dump_stats(&self) {
		debug!(
			LOGGER,
			"pmmr backend: unpruned: {}, hashes: {}",
			self.unpruned_size().unwrap_or(0),
			self.hash_size().unwrap_or(0),
		);
	}
}

impl<T> PMMRDBBackend<T>
where
	T: PMMRable + ::std::fmt::Debug,
{
	/// Instantiates a new PMMR backend.
	/// Use the provided dir to store its files.
	pub fn new(data_dir: String) -> io::Result<PMMRDBBackend<T>> {
		let hash_file = AppendOnlyFile::open(format!("{}/{}", data_dir, PMMR_HASH_FILE))?;

		Ok(PMMRDBBackend {
			data_dir,
			hash_file,
			_marker: marker::PhantomData,
		})
	}

	/// Number of elements in the PMMR stored by this backend. Only produces the
	/// fully sync'd size.
	pub fn unpruned_size(&self) -> io::Result<u64> {
		let record_len = 32;
		let sz = self.hash_file.size()?;
		Ok(sz / record_len)
	}

	/// Size of the underlying hashed data. Extremely dependent on pruning
	/// and compaction.
	pub fn hash_size(&self) -> io::Result<u64> {
		self.hash_file.size().map(|sz| sz / 32)
	}

	/// Syncs all files to disk. A call to sync is required to ensure all the
	/// data has been successfully written to disk.
	pub fn sync(&mut self) -> io::Result<()> {
		if let Err(e) = self.hash_file.flush() {
			return Err(io::Error::new(
				io::ErrorKind::Interrupted,
				format!("Could not write to log hash storage, disk full? {:?}", e),
			));
		}
		Ok(())
	}

	/// Discard the current, non synced state of the backend.
	pub fn discard(&mut self) {
		self.hash_file.discard();
	}
}
