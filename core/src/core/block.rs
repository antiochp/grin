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

//! Blocks and blockheaders

use time;
use secp::{self, Secp256k1};
use secp::key::SecretKey;
use secp::pedersen::Commitment;
use std::collections::{HashMap, HashSet};

use core::Committed;
use core::{Input, Output, Proof, TxKernel, Transaction, COINBASE_KERNEL, COINBASE_OUTPUT};
use core::transaction::merkle_inputs_outputs;
use consensus::REWARD;
use consensus::MINIMUM_DIFFICULTY;
use core::hash::{Hash, Hashed, ZERO_HASH};
use core::target::Difficulty;
use ser::{self, Readable, Reader, Writeable, Writer};
use global;



bitflags! {
    /// Options for block validation
    pub flags BlockFeatures: u8 {
        /// No flags
        const DEFAULT_BLOCK = 0b00000000,
    }
}

/// Block header, fairly standard compared to other blockchains.
#[derive(Debug, PartialEq)]
pub struct BlockHeader {
	/// Height of this block since the genesis block (height 0)
	pub height: u64,
	/// Hash of the block previous to this in the chain.
	pub previous: Hash,
	/// Timestamp at which the block was built.
	pub timestamp: time::Tm,
	/// Merkle root of the UTXO set
	pub utxo_merkle: Hash,
	/// Merkle tree of hashes for all inputs, outputs and kernels in the block
	pub tx_merkle: Hash,
	/// Features specific to this block, allowing possible future extensions
	pub features: BlockFeatures,
	/// Nonce increment used to mine this block.
	pub nonce: u64,
	/// Proof of work data.
	pub pow: Proof,
	/// Difficulty used to mine the block.
	pub difficulty: Difficulty,
	/// Total accumulated difficulty since genesis block
	pub total_difficulty: Difficulty,
}

impl Default for BlockHeader {
	fn default() -> BlockHeader {
		let proof_size = global::proofsize();
		BlockHeader {
			height: 0,
			previous: ZERO_HASH,
			timestamp: time::at_utc(time::Timespec { sec: 0, nsec: 0 }),
			difficulty: Difficulty::from_num(MINIMUM_DIFFICULTY),
			total_difficulty: Difficulty::from_num(MINIMUM_DIFFICULTY),
			utxo_merkle: ZERO_HASH,
			tx_merkle: ZERO_HASH,
			features: DEFAULT_BLOCK,
			nonce: 0,
			pow: Proof::zero(proof_size),
		}
	}
}

/// Serialization of a block header
impl Writeable for BlockHeader {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		ser_multiwrite!(writer,
		                [write_u64, self.height],
		                [write_fixed_bytes, &self.previous],
		                [write_i64, self.timestamp.to_timespec().sec],
		                [write_fixed_bytes, &self.utxo_merkle],
		                [write_fixed_bytes, &self.tx_merkle],
		                [write_u8, self.features.bits()]);

		try!(writer.write_u64(self.nonce));
		try!(self.difficulty.write(writer));
		try!(self.total_difficulty.write(writer));

		if writer.serialization_mode() != ser::SerializationMode::Hash {
			try!(self.pow.write(writer));
		}
		Ok(())
	}
}

/// Deserialization of a block header
impl Readable for BlockHeader {
	fn read(reader: &mut Reader) -> Result<BlockHeader, ser::Error> {
		let height = try!(reader.read_u64());
		let previous = try!(Hash::read(reader));
		let timestamp = reader.read_i64()?;
		let utxo_merkle = try!(Hash::read(reader));
		let tx_merkle = try!(Hash::read(reader));
		let (features, nonce) = ser_multiread!(reader, read_u8, read_u64);
		let difficulty = try!(Difficulty::read(reader));
		let total_difficulty = try!(Difficulty::read(reader));
		let pow = try!(Proof::read(reader));

		Ok(BlockHeader {
			height: height,
			previous: previous,
			timestamp: time::at_utc(time::Timespec {
				sec: timestamp,
				nsec: 0,
			}),
			utxo_merkle: utxo_merkle,
			tx_merkle: tx_merkle,
			features: BlockFeatures::from_bits(features).ok_or(ser::Error::CorruptedData)?,
			pow: pow,
			nonce: nonce,
			difficulty: difficulty,
			total_difficulty: total_difficulty,
		})
	}
}

/// A block as expressed in the MimbleWimble protocol. The reward is
/// non-explicit, assumed to be deducible from block height (similar to
/// bitcoin's schedule) and expressed as a global transaction fee (added v.H),
/// additive to the total of fees ever collected.
#[derive(Debug)]
pub struct Block {
	/// The header with metadata and commitments to the rest of the data
	pub header: BlockHeader,
	/// Transaction inputs indexed by their commitments
	pub inputs: HashMap<Commitment, Input>,
	/// Transaction outputs indexed by their commitments
	pub outputs: HashMap<Commitment, Output>,
	/// List of transaction kernels and associated proofs
	pub kernels: Vec<TxKernel>,
}

/// Implementation of Writeable for a block, defines how to write the block to a
/// binary writer. Differentiates between writing the block for the purpose of
/// full serialization and the one of just extracting a hash.
impl Writeable for Block {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		try!(self.header.write(writer));

		if writer.serialization_mode() != ser::SerializationMode::Hash {
			ser_multiwrite!(writer,
			                [write_u64, self.inputs.len() as u64],
			                [write_u64, self.outputs.len() as u64],
			                [write_u64, self.kernels.len() as u64]);

			for (_, inp) in &self.inputs {
				try!(inp.write(writer));
			}
			for (_, out) in &self.outputs {
				try!(out.write(writer));
			}
			for proof in &self.kernels {
				try!(proof.write(writer));
			}
		}
		Ok(())
	}
}

/// Implementation of Readable for a block, defines how to read a full block
/// from a binary stream.
impl Readable for Block {
	fn read(reader: &mut Reader) -> Result<Block, ser::Error> {
		let header = try!(BlockHeader::read(reader));

		let (input_len, output_len, proof_len) =
			ser_multiread!(reader, read_u64, read_u64, read_u64);

        let mut inputs = HashMap::new();
        for _ in 0..input_len {
            let input = try!(Input::read(reader));
            inputs.insert(input.commitment(), input);
        };

        let mut outputs = HashMap::new();
        for _ in 0..output_len {
            let output = try!(Output::read(reader));
            outputs.insert(output.commitment(), output);
        };

		let kernels = try!((0..proof_len).map(|_| TxKernel::read(reader)).collect());

		Ok(Block {
			header: header,
			inputs: inputs,
			outputs: outputs,
			kernels: kernels,
			..Default::default()
		})
	}
}

/// Provides all information from a block that allows the calculation of total
/// Pedersen commitment.
impl Committed for Block {
	fn inputs_committed(&self) -> Vec<Input> {
        self.inputs.values().map(|&inp| inp).collect::<Vec<_>>().clone()
	}

	fn outputs_committed(&self) -> Vec<Output> {
        self.outputs.values().map(|&out| out).collect::<Vec<_>>().clone()
	}

	fn overage(&self) -> i64 {
		(self.total_fees() as i64) - (REWARD as i64)
	}
}

/// Default properties for a block, everything zeroed out and empty vectors.
impl Default for Block {
	fn default() -> Block {
		Block {
			header: Default::default(),
			inputs: HashMap::new(),
			outputs: HashMap::new(),
			kernels: vec![],
		}
	}
}

impl Block {
	/// Builds a new block from the header of the previous block, a vector of
	/// transactions and the private key that will receive the reward. Checks
	/// that all transactions are valid and calculates the Merkle tree.
	pub fn new(prev: &BlockHeader,
	           txs: Vec<&Transaction>,
	           reward_key: SecretKey)
	           -> Result<Block, secp::Error> {

		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit);
		let (reward_out, reward_proof) = try!(Block::reward_output(reward_key, &secp));

		Block::with_reward(prev, txs, reward_out, reward_proof)
	}

	/// Builds a new block ready to mine from the header of the previous block,
	/// a vector of transactions and the reward information. Checks
	/// that all transactions are valid and calculates the Merkle tree.
	pub fn with_reward(prev: &BlockHeader,
	                   txs: Vec<&Transaction>,
	                   reward_out: Output,
	                   reward_kern: TxKernel)
	                   -> Result<Block, secp::Error> {
		// note: the following reads easily but may not be the most efficient due to
		// repeated iterations, revisit if a problem
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit);

		// validate each transaction and gather their kernels
		let mut kernels = try_map_vec!(txs, |tx| tx.verify_sig(&secp));
		kernels.push(reward_kern);

        let mut inputs = HashMap::new();
        let mut outputs = HashMap::new();
        for tx in txs {
            for input in &tx.inputs {
                inputs.insert(input.commitment(), *input);
            }
            for output in &tx.outputs {
                outputs.insert(output.commitment(), *output);
            }
        };

		outputs.insert(reward_out.commitment(), reward_out);

		// calculate the overall Merkle tree and fees

		Ok(Block {
				header: BlockHeader {
					height: prev.height + 1,
					timestamp: time::now(),
					previous: prev.hash(),
					total_difficulty: prev.pow.clone().to_difficulty() + prev.total_difficulty.clone(),
					..Default::default()
				},
				inputs: inputs,
				outputs: outputs,
				kernels: kernels,
			}
			.compact())
	}


	/// Blockhash, computed using only the header
	pub fn hash(&self) -> Hash {
		self.header.hash()
	}

	/// Sum of all fees (inputs less outputs) in the block
	pub fn total_fees(&self) -> u64 {
		self.kernels.iter().map(|p| p.fee).sum()
	}

	/// Matches any output with a potential spending input, eliminating them
	/// from the block. Provides a simple way to compact the block.
	pub fn compact(&self) -> Block {
        let in_set = self.inputs.keys().map(|&commit| commit).collect::<HashSet<Commitment>>();
        let out_set = self.outputs.keys().map(|&commit| commit).collect::<HashSet<Commitment>>();
        let intersect = in_set.intersection(&out_set).collect::<HashSet<_>>();

        // the chosen ones
        let mut new_inputs = self.inputs.clone();
        new_inputs.retain(|commit, _| !intersect.contains(commit));

        let mut new_outputs = self.outputs.clone();
        new_outputs.retain(|commit, _| !intersect.contains(commit));

        let inputs_for_merkle = new_inputs.values().map(|&inp| inp).collect::<Vec<_>>();
        let outputs_for_merkle = new_outputs.values().map(|&out| out).collect::<Vec<_>>();

		let tx_merkle = merkle_inputs_outputs(inputs_for_merkle, outputs_for_merkle);

		Block {
			header: BlockHeader {
				tx_merkle: tx_merkle,
				pow: self.header.pow.clone(),
				difficulty: self.header.difficulty.clone(),
				total_difficulty: self.header.total_difficulty.clone(),
				..self.header
			},
			inputs: new_inputs,
			outputs: new_outputs,
			kernels: self.kernels.clone(),
		}
	}

	/// Merges the 2 blocks, essentially appending the inputs, outputs and
	/// kernels.
	/// Also performs a compaction on the result.
	pub fn merge(&self, other: Block) -> Block {
		let mut all_inputs = self.inputs.clone();
        for (commit, inp) in other.inputs {
            all_inputs.insert(commit.clone(), inp.clone());
        };

		let mut all_outputs = self.outputs.clone();
        for (commit, out) in other.outputs {
            all_outputs.insert(commit.clone(), out.clone());
        };

		let mut all_kernels = self.kernels.clone();
		all_kernels.append(&mut other.kernels.clone());

		Block {
				// compact will fix the merkle tree
				header: BlockHeader {
					pow: self.header.pow.clone(),
					difficulty: self.header.difficulty.clone(),
					total_difficulty: self.header.total_difficulty.clone(),
					..self.header
				},
				inputs: all_inputs,
				outputs: all_outputs,
				kernels: all_kernels,
			}
			.compact()
	}

	/// Validates all the elements in a block that can be checked without
	/// additional
	/// data. Includes commitment sums and kernels, Merkle trees, reward, etc.
	pub fn validate(&self, secp: &Secp256k1) -> Result<(), secp::Error> {
		self.verify_coinbase(secp)?;
		self.verify_kernels(secp)?;
        self.verify_merkle_inputs_outputs()?;
        Ok(())
	}

    /// Verify the transaction Merkle root
    pub fn verify_merkle_inputs_outputs(&self) -> Result<(), secp::Error> {
        // TODO - investigate how to use map_vec! or even skip this map step somehow?
        let inputs_for_merkle = self.inputs.values().map(|&inp| inp).collect::<Vec<_>>();
        let outputs_for_merkle = self.outputs.values().map(|&out| out).collect::<Vec<_>>();

        let tx_merkle = merkle_inputs_outputs(inputs_for_merkle, outputs_for_merkle);

        if tx_merkle != self.header.tx_merkle {
            // TODO more specific error
            return Err(secp::Error::IncorrectCommitSum);
        }
        Ok(())
    }

	/// Validate the sum of input/output commitments match the sum in kernels
	/// and
	/// that all kernel signatures are valid.
	pub fn verify_kernels(&self, secp: &Secp256k1) -> Result<(), secp::Error> {
		// sum all inputs and outs commitments
		let io_sum = self.sum_commitments(secp)?;

		// sum all kernels commitments
		let proof_commits = map_vec!(self.kernels, |proof| proof.excess);
		let proof_sum = secp.commit_sum(proof_commits, vec![])?;

		// both should be the same
		if proof_sum != io_sum {
			// TODO more specific error
			return Err(secp::Error::IncorrectCommitSum);
		}

		// verify all signatures with the commitment as pk
		for proof in &self.kernels {
			proof.verify(secp)?;
		}
		Ok(())
	}

	// Validate the coinbase outputs generated by miners. Entails 2 main checks:
	//
	// * That the sum of all coinbase-marked outputs equal the supply.
	// * That the sum of blinding factors for all coinbase-marked outputs match
	//   the coinbase-marked kernels.
	fn verify_coinbase(&self, secp: &Secp256k1) -> Result<(), secp::Error> {
        let mut cb_outs = HashMap::new();
        for (commit, out) in &self.outputs {
            if out.features.intersects(COINBASE_OUTPUT) {
                cb_outs.insert(commit.clone(), out.clone());
            };
        };

		let cb_kerns = self.kernels
			.iter()
			.filter(|k| k.features.intersects(COINBASE_KERNEL))
			.map(|k| k.clone())
			.collect::<Vec<_>>();

		// verifying the kernels on a block composed of just the coinbase outputs
		// and kernels checks all we need
		Block {
				header: BlockHeader::default(),
				inputs: HashMap::new(),
				outputs: cb_outs,
				kernels: cb_kerns,
			}
			.verify_kernels(secp)
	}

	/// Builds the blinded output and related signature proof for the block
	/// reward.
	pub fn reward_output(skey: secp::key::SecretKey,
	                     secp: &Secp256k1)
	                     -> Result<(Output, TxKernel), secp::Error> {
		let msg = try!(secp::Message::from_slice(&[0; secp::constants::MESSAGE_SIZE]));
		let sig = try!(secp.sign(&msg, &skey));
		let commit = secp.commit(REWARD, skey).unwrap();
		let rproof = secp.range_proof(0, REWARD, skey, commit);

		let output = Output {
			features: COINBASE_OUTPUT,
			commit: commit,
			proof: rproof,
		};

		let over_commit = try!(secp.commit_value(REWARD as u64));
		let out_commit = output.commitment();
		let excess = try!(secp.commit_sum(vec![out_commit], vec![over_commit]));

		let proof = TxKernel {
			features: COINBASE_KERNEL,
			excess: excess,
			excess_sig: sig.serialize_der(&secp),
			fee: 0,
		};
		Ok((output, proof))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use core::Transaction;
	use core::build::{self, input, output, input_rand, output_rand, with_fee};
	use core::test::tx2i1o;

	use secp::{self, Secp256k1};
	use secp::key::SecretKey;
	use rand::os::OsRng;

	fn new_secp() -> Secp256k1 {
		secp::Secp256k1::with_caps(secp::ContextFlag::Commit)
	}

	// utility to create a block without worrying about the key or previous
	// header
	fn new_block(txs: Vec<&Transaction>, secp: &Secp256k1) -> Block {
		let mut rng = OsRng::new().unwrap();
		let skey = SecretKey::new(secp, &mut rng);
		Block::new(&BlockHeader::default(), txs, skey).unwrap()
	}

	// utility producing a transaction that spends an output with the provided
	// value and blinding key
	fn txspend1i1o(v: u64, b: SecretKey) -> Transaction {
		build::transaction(vec![input(v, b), output_rand(3), with_fee(1)])
			.map(|(tx, _)| tx)
			.unwrap()
	}

	#[test]
	// builds a block with a tx spending another and check if merging occurred
	fn compactable_block() {
		let mut rng = OsRng::new().unwrap();
		let ref secp = new_secp();

		let mut btx1 = tx2i1o();
		let skey = SecretKey::new(secp, &mut rng);
		let (mut btx2, _) = build::transaction(vec![input_rand(5), output(4, skey), with_fee(1)])
			.unwrap();

		// spending tx2
		let mut btx3 = txspend1i1o(4, skey);
		let b = new_block(vec![&mut btx1, &mut btx2, &mut btx3], secp);

		// block should have been automatically compacted (including reward
		// output) and should still be valid
		b.validate(&secp).unwrap();
		assert_eq!(b.inputs.len(), 3);
		assert_eq!(b.outputs.len(), 3);
	}

	#[test]
	// builds 2 different blocks with a tx spending another and check if merging
	// occurs
	fn mergeable_blocks() {
		let mut rng = OsRng::new().unwrap();
		let ref secp = new_secp();

		let mut btx1 = tx2i1o();
		let skey = SecretKey::new(secp, &mut rng);
		let (mut btx2, _) = build::transaction(vec![input_rand(5), output(4, skey), with_fee(1)])
			.unwrap();

		// spending tx2
		let mut btx3 = txspend1i1o(4, skey);

		let b1 = new_block(vec![&mut btx1, &mut btx2], secp);
		b1.validate(&secp).unwrap();
		let b2 = new_block(vec![&mut btx3], secp);
		b2.validate(&secp).unwrap();

		// block should have been automatically compacted and should still be valid
		let b3 = b1.merge(b2);
		assert_eq!(b3.inputs.len(), 3);
		assert_eq!(b3.outputs.len(), 4);
	}

    #[test]
    fn empty_block_with_coinbase_is_valid() {
        let ref secp = new_secp();
        let b = new_block(vec![], secp);

        assert_eq!(b.inputs.len(), 0);
        assert_eq!(b.outputs.len(), 1);
        assert_eq!(b.kernels.len(), 1);

        let coinbase_outputs = b.outputs
			.values()
			.filter(|out| out.features.contains(COINBASE_OUTPUT))
            .map(|o| o.clone())
			.collect::<Vec<_>>();
        assert_eq!(coinbase_outputs.len(), 1);

        let coinbase_kernels = b.kernels
			.iter()
			.filter(|out| out.features.contains(COINBASE_KERNEL))
            .map(|o| o.clone())
			.collect::<Vec<_>>();
        assert_eq!(coinbase_kernels.len(), 1);

        // the block should be valid here (single coinbase output with corresponding txn kernel)
        assert_eq!(b.validate(&secp), Ok(()));
    }


    #[test]
    // test that flipping the COINBASE_OUTPUT flag on the output features
    // invalidates the block and specifically it causes verify_coinbase to fail
    // additionally verifying the merkle_inputs_outputs also fails
    fn remove_coinbase_output_flag() {
        let ref secp = new_secp();
        let b = new_block(vec![], secp);
        let out = b.outputs.values().next().unwrap();
        assert!(out.features.contains(COINBASE_OUTPUT));

        let mut tweaked_out = out.clone();
        tweaked_out.features.remove(COINBASE_OUTPUT);

        let mut new_outputs: HashMap<Commitment, Output> = HashMap::new();
        new_outputs.insert(tweaked_out.commitment(), tweaked_out);

        let tweaked_block = Block {
            outputs: new_outputs,
            .. b
        };

        assert_eq!(tweaked_block.verify_coinbase(&secp), Err(secp::Error::IncorrectCommitSum));
        assert_eq!(tweaked_block.verify_kernels(&secp), Ok(()));
        assert_eq!(tweaked_block.verify_merkle_inputs_outputs(), Err(secp::Error::IncorrectCommitSum));

        assert_eq!(tweaked_block.validate(&secp), Err(secp::Error::IncorrectCommitSum));
    }

    #[test]
    // test that flipping the COINBASE_KERNEL flag on the kernel features
    // invalidates the block and specifically it causes verify_coinbase to fail
    fn remove_coinbase_kernel_flag() {
        let ref secp = new_secp();
        let mut b = new_block(vec![], secp);

        assert!(b.kernels[0].features.contains(COINBASE_KERNEL));
        b.kernels[0].features.remove(COINBASE_KERNEL);

        assert_eq!(b.verify_coinbase(&secp), Err(secp::Error::IncorrectCommitSum));
        assert_eq!(b.verify_kernels(&secp), Ok(()));
        assert_eq!(b.verify_merkle_inputs_outputs(), Ok(()));

        assert_eq!(b.validate(&secp), Err(secp::Error::IncorrectCommitSum));
    }

    #[test]
    fn serialize_deserialize_block() {
        let ref secp = new_secp();
        let b = new_block(vec![], secp);

        let mut vec = Vec::new();
        ser::serialize(&mut vec, &b).expect("serialization failed");
        let b2: Block = ser::deserialize(&mut &vec[..]).unwrap();

        assert_eq!(b.inputs, b2.inputs);
        assert_eq!(b.outputs, b2.outputs);
        assert_eq!(b.kernels, b2.kernels);

        // TODO - timestamps are not coming back equal here (UTC related?) -
        // assert_eq!(b.header, b2.header);
        // timestamp: Tm { tm_sec: 51, tm_min: 7, tm_hour: 23, tm_mday: 20, tm_mon: 7, tm_year: 117, tm_wday: 0, tm_yday: 231, tm_isdst: 1, tm_utcoff: -14400, tm_nsec: 780878000 },
        // timestamp: Tm { tm_sec: 51, tm_min: 7, tm_hour: 3, tm_mday: 21, tm_mon: 7, tm_year: 117, tm_wday: 1, tm_yday: 232, tm_isdst: 0, tm_utcoff: 0, tm_nsec: 0 },
    }
}
