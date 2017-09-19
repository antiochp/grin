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

use core::core;
use chain;
use secp::pedersen;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tip {
	/// Height of the tip (max height of the fork)
	pub height: u64,
	// Last block pushed to the fork
	// pub last_block_h: Hash,
	// Block previous to last
	// pub prev_block_h: Hash,
	// Total difficulty accumulated on that fork
	// pub total_difficulty: Difficulty,
}

impl Tip {
	pub fn from_tip(tip: chain::Tip) -> Tip {
		Tip {
			height: tip.height,
		}
	}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Utxo {
	/// Options for an output's structure or use
	pub features: core::OutputFeatures,
	/// The homomorphic commitment representing the output's amount
	pub commit: pedersen::Commitment,
	/// A proof that the commitment is in the right range
	pub proof: pedersen::RangeProof,
	/// The height of the block creating this output
	pub height: u64,
}

impl Utxo {
	pub fn from_output(output: core::Output) -> Utxo {
		Utxo {
			features: output.features,
			commit: output.commit,
			proof: output.proof,
			height: 0,
		}
	}
}

#[derive(Serialize, Deserialize)]
pub struct PoolInfo {
	/// Size of the pool
	pub pool_size: usize,
	/// Size of orphans
	pub orphans_size: usize,
	/// Total size of pool + orphans
	pub total_size: usize,
}
