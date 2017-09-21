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

extern crate router;
extern crate bodyparser;

use types::*;
use extkey::ExtendedKey;
use api;
use api::TxWrapper;
use core::ser;
use core::core::{Block, Transaction, TxKernel, Output, build};
use secp;
use secp::key::SecretKey;
use util;

use iron::prelude::*;
use iron::Handler;
use iron::status;
use hyper::mime::*;
use router::Router;
use serde_json;

use std::sync::{Arc, RwLock};


pub struct JsonTxHandler {
	pub ext_key: ExtendedKey,
	pub config: WalletConfig,
}

impl Handler for JsonTxHandler {
	fn handle(&self, req: &mut Request) -> IronResult<Response> {
		let content_type = mime!(Application/Json);

		println!("***** in JsonTxHandler handle");

		let txn = req.get::<bodyparser::Struct<JSONPartialTx>>().map_err(|_| {
			Error::Format(format!("Invalid json in body."))
		})?.unwrap();

		receive_json_tx(&self.config, &self.ext_key, &txn).map_err(|e| {
			api::Error::Internal(format!("Error processing partial transaction: {:?}", e))
		}).unwrap();


		Ok(Response::with((content_type, status::Ok, "{}")))
	}
}

pub struct CoinbaseHandler {
	pub ext_key: ExtendedKey,
	pub config: WalletConfig,
}

impl Handler for CoinbaseHandler {
	fn handle(&self, req: &mut Request) -> IronResult<Response> {
		let content_type = mime!(Application/Json);

		println!("***** in CoinbaseHandler handle");

		let txn = req.get::<bodyparser::Struct<CoinbaseTx>>().
			map_err(|_| {
				Error::Format(format!("Invalid json in body."))
			})?.unwrap();

		// TODO - get rid of unwrap() above

		if txn.amount == 0 {
			let error = api::Error::Argument(format!("Zero amount not allowed."));
			return Err(IronError::new(error, status::BadRequest));
		}
		let (out, kern) = receive_coinbase(&self.config, &self.ext_key, txn.amount).map_err(|e| {
			api::Error::Internal(format!("Error building coinbase: {:?}", e))
		})?;
		let out_bin = ser::ser_vec(&out).map_err(|e| {
			api::Error::Internal(format!("Error serializing output: {:?}", e))
		})?;
		let kern_bin = ser::ser_vec(&kern).map_err(|e| {
			api::Error::Internal(format!("Error serializing kernel: {:?}", e))
		})?;

		let cb_data = CbData {
			output: util::to_hex(out_bin),
			kernel: util::to_hex(kern_bin),
		};
		let json = serde_json::to_string(&cb_data)
			.map_err(|e| IronError::new(e, status::InternalServerError))?;

		Ok(Response::with((content_type, status::Ok, json)))
	}
}

/// Build a coinbase output and the corresponding kernel
fn receive_coinbase(config: &WalletConfig, ext_key: &ExtendedKey, amount: u64) -> Result<(Output, TxKernel), Error> {
	let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);

	// operate within a lock on wallet data
	WalletData::with_wallet(&config.data_file_dir, |wallet_data| {

		// derive a new private for the reward
		let next_child = wallet_data.next_child(&ext_key.fingerprint);
		let coinbase_key = ext_key.derive(&secp, next_child).map_err(|e| Error::Key(e))?;

		// track the new output and return the stuff needed for reward
		wallet_data.append_output(OutputData {
			fingerprint: coinbase_key.fingerprint,
			n_child: coinbase_key.n_child,
			value: amount,
			status: OutputStatus::Unconfirmed,
			height: 0,
		});
		debug!("Using child {} for a new coinbase output.",
		       coinbase_key.n_child);

		Block::reward_output(coinbase_key.key, &secp).map_err(&From::from)
	})?
}

/// Receive an already well formed JSON transaction issuance and finalize the
/// transaction, adding our receiving output, to broadcast to the rest of the
/// network.
pub fn receive_json_tx(
	config: &WalletConfig,
	ext_key: &ExtendedKey, txn: &JSONPartialTx
) -> Result<(), Error> {
	let (amount, blinding, partial_tx) = partial_tx_from_json(txn.clone())?;
	let final_tx = receive_transaction(&config, ext_key, amount, blinding, partial_tx)?;
	let tx_hex = util::to_hex(ser::ser_vec(&final_tx).unwrap());

	let url = format!("{}/v1/pool/push", config.check_node_api_http_addr.as_str());
	let _: TxWrapper = api::client::post(url.as_str(), &TxWrapper { tx_hex: tx_hex })?;
	Ok(())
}

pub fn receive_json_tx_from_str(
	config: &WalletConfig,
	ext_key: &ExtendedKey, json_str: &str
) -> Result<(), Error> {
	let partial_tx: JSONPartialTx = serde_json::from_str(json_str)?;
	receive_json_tx(config, ext_key, &partial_tx)
}

/// Reads a partial transaction encoded as JSON into the amount, sum of blinding
/// factors and the transaction itself.
pub fn partial_tx_from_json(
	partial_tx: JSONPartialTx
) -> Result<(u64, SecretKey, Transaction), Error> {
	let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);
	let blind_bin = util::from_hex(partial_tx.blind_sum)?;
	let blinding = SecretKey::from_slice(&secp, &blind_bin[..])?;
	let tx_bin = util::from_hex(partial_tx.tx)?;
	let tx = ser::deserialize(&mut &tx_bin[..]).map_err(|_| {
		Error::Format("Could not deserialize transaction, invalid format.".to_string())
	})?;
	Ok((partial_tx.amount, blinding, tx))
}

/// Builds a full transaction from the partial one sent to us for transfer
fn receive_transaction(config: &WalletConfig,
					   ext_key: &ExtendedKey,
                       amount: u64,
                       blinding: SecretKey,
                       partial: Transaction)
                       -> Result<Transaction, Error> {

	let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);

	// operate within a lock on wallet data
	WalletData::with_wallet(&config.data_file_dir, |wallet_data| {

		let next_child = wallet_data.next_child(&ext_key.fingerprint);
		let out_key = ext_key.derive(&secp, next_child).map_err(|e| Error::Key(e))?;

		let (tx_final, _) = build::transaction(vec![
			build::initial_tx(partial),
			build::with_excess(blinding),
			build::output(amount, out_key.key)
		])?;

		// make sure the resulting transaction is valid (could have been lied to
		// on excess)
		tx_final.validate(&secp)?;

		// track the new output and return the finalized transaction to broadcast
		wallet_data.append_output(OutputData {
			fingerprint: out_key.fingerprint,
			n_child: out_key.n_child,
			value: amount,
			status: OutputStatus::Unconfirmed,
			height: 0,
		});

		debug!("Using child {} for a new transaction output.", out_key.n_child);

		Ok(tx_final)
	})?
}
