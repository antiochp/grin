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

use std::sync::{Arc, RwLock};

use chain;
use core::core;
use core::ser;
use pool;
use util;

use types::{Error, Tip, Utxo};
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

pub struct UtxoHandler {
	pub chain: Arc<chain::Chain>,
}

impl Handler for UtxoHandler {
	fn handle(&self, req: &mut Request) -> IronResult<Response> {
		let content_type = mime!(Application/Json);

		println!("*** in v2 utxo handler");

		let id = req.extensions.get::<Router>().unwrap().find("id").unwrap_or("/");
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
