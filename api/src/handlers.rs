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

use std::sync::{Arc, RwLock};

use chain;
use core::core;
use core::ser;
use pool;
use util;

use types::*;
use secp::pedersen::Commitment;


use iron::prelude::*;
use iron::Handler;
use iron::status;
use hyper::mime::*;
use router::Router;
use serde_json;


pub struct ChainHandler {
	pub chain: Arc<chain::Chain>,
}

impl Handler for ChainHandler {
	fn handle(&self, req: &mut Request) -> IronResult<Response> {
		let content_type = mime!(Application/Json);

		println!("***** in v2 chain_handle handle");

		match self.chain.head() {
			Ok(head) => {
				let json = serde_json::to_string(&head)
					.map_err(|e| IronError::new(e, status::InternalServerError))?;
				Ok(Response::with((content_type, status::Ok, json)))
			},
			Err(e) => {
				// TODO - can we avoid wrapping an error in an error and wrapping it in an IronError?
				let error = Error::Internal(format!("{:?}", e));
				Err(IronError::new(error, status::BadRequest))
			}
		}
	}
}

pub struct PoolPushHandler<T> {
	pub tx_pool: Arc<RwLock<pool::TransactionPool<T>>>,
}

impl<T> Handler for PoolPushHandler<T>
	where T: pool::BlockChain + Clone + Send + Sync + 'static
{
	fn handle(&self, req: &mut Request) -> IronResult<Response> {
		let content_type = mime!(Application/Json);

		println!("*** in v2 pool push handler");

		let tx_wrap = req.get::<bodyparser::Struct<TxWrapper>>().
			map_err(|_| {
				Error::Argument(format!("Invalid json in body."))
			})?.unwrap();

		// TODO - cleanup the unwrap above

		let tx_bin = util::from_hex(tx_wrap.tx_hex).
			map_err(|_| {
				Error::Argument(format!("Invalid hex in transaction wrapper."))
			})?;

		let tx: core::Transaction = ser::deserialize(&mut &tx_bin[..]).
			map_err(|_| {
				Error::Argument(format!("Could not deserialize transaction, invalid format."))
			})?;

		let source = pool::TxSource {
			debug_name: "push-api".to_string(),
			identifier: "?.?.?.?".to_string(),
		};

		debug!(
			"Pushing transaction with {} inputs and {} outputs to pool.",
			tx.inputs.len(),
			tx.outputs.len()
		);

		self.tx_pool
			.write()
			.unwrap()
			.add_to_memory_pool(source, tx)
			.map_err(|e| {
				Error::Internal(format!("Addition to transaction pool failed: {:?}", e))
			})?;

		Ok(Response::with((content_type, status::Ok, "{}")))
	}
}

pub struct PoolInfoHandler<T> {
	pub tx_pool: Arc<RwLock<pool::TransactionPool<T>>>,
}

impl<T> Handler for PoolInfoHandler<T>
	where T: pool::BlockChain + Clone + Send + Sync + 'static
{
	fn handle(&self, req: &mut Request) -> IronResult<Response> {
		let content_type = mime!(Application/Json);

		println!("*** in v2 pool info handler");

		match self.tx_pool.read() {
			Ok(pool) => {
				let pool_info = PoolInfo {
					pool_size: pool.pool_size(),
					orphans_size: pool.orphans_size(),
					total_size: pool.total_size(),
				};
				let json = serde_json::to_string(&pool_info)
					.map_err(|e| IronError::new(e, status::InternalServerError))?;
				Ok(Response::with((content_type, status::Ok, json)))
			},
			Err(e) => {
				let error = Error::Internal(format!("{:?}", e));
				Err(IronError::new(error, status::BadRequest))
			}
		}
	}
}

pub struct UtxoHandler {
	pub chain: Arc<chain::Chain>,
}

impl Handler for UtxoHandler {
	fn handle(&self, req: &mut Request) -> IronResult<Response> {
		let content_type = mime!(Application/Json);

		println!("*** in v2 utxo handler");

		let id = req.extensions.get::<Router>().unwrap().find("id").unwrap_or("/");
		// let ids = comma seprated list of ids from query param

		let c = util::from_hex(String::from(id)).map_err(|_|
			Error::Argument(format!("Not a valid commitment: {}", id)))?;

		// TODO - can probably clean up the error mapping here
		let commit = Commitment::from_vec(c);
		match self.chain.get_unspent(&commit) {
			Ok(out) => {
				let mut utxo = Utxo::from_output(out);
				match self.chain.get_block_header_by_output_commit(&commit) {
					Ok(header) => {
						utxo.height = header.height;
						let json = serde_json::to_string(&utxo)
							.map_err(|e| IronError::new(e, status::InternalServerError))?;
						Ok(Response::with((content_type, status::Ok, json)))
					},
					Err(_) => Err(IronError::from(Error::NotFound)),
				}
			},
			Err(_) => Err(IronError::from(Error::NotFound)),
		}
	}
}
