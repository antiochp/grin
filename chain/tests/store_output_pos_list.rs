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

use grin_chain as chain;
use grin_core as core;
use grin_util as util;

use crate::chain::linked_list::{self, FooLinkedList, LinkedList};
use crate::chain::store::{self, ChainStore};
use crate::chain::types::{CommitPos, OutputPos};
use crate::core::core::OutputFeatures;
use crate::util::secp::pedersen::Commitment;
mod chain_test_helper;

use self::chain_test_helper::clean_output_dir;

#[test]
fn test_store_output_pos_list() {
	util::init_test_logger();

	let chain_dir = ".grin_idx_1";
	clean_output_dir(chain_dir);

	let store = ChainStore::new(chain_dir).unwrap();

	let batch = store.batch().unwrap();

	let commit = Commitment::from_vec(vec![]);

	let index = linked_list::output_plain_index();

	assert_eq!(index.get_list(&batch, commit), Ok(None));

	assert_eq!(
		index.push_entry(
			&batch,
			commit,
			OutputPos {
				pos: 1,
				height: 1,
				features: OutputFeatures::Plain,
			},
		),
		Ok(()),
	);

	assert_eq!(
		index.get_list(&batch, commit),
		Ok(Some(LinkedList::Unique {
			pos: OutputPos {
				pos: 1,
				height: 1,
				features: OutputFeatures::Plain
			}
		})),
	);

	assert_eq!(
		index.push_entry(
			&batch,
			commit,
			OutputPos {
				pos: 2,
				height: 2,
				features: OutputFeatures::Plain,
			},
		),
		Ok(()),
	);

	assert_eq!(
		index.get_list(&batch, commit),
		Ok(Some(LinkedList::Multi { head: 2, tail: 1 })),
	);

	assert_eq!(
		index.push_entry(
			&batch,
			commit,
			OutputPos {
				pos: 3,
				height: 3,
				features: OutputFeatures::Plain,
			},
		),
		Ok(()),
	);

	assert_eq!(
		index.get_list(&batch, commit),
		Ok(Some(LinkedList::Multi { head: 3, tail: 1 })),
	);

	assert_eq!(
		index.pop_entry(&batch, commit,),
		Ok(Some(OutputPos {
			pos: 3,
			height: 3,
			features: OutputFeatures::Plain,
		})),
	);

	assert_eq!(
		index.get_list(&batch, commit),
		Ok(Some(LinkedList::Multi { head: 2, tail: 1 })),
	);

	// Cleanup chain directory
	clean_output_dir(chain_dir);
}
