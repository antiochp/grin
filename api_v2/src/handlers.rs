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

use types::Error;

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
		println!("***** in v2 chain_handle handle");
		let content_type = mime!(Application/Json);

		match self.chain.head() {
			Ok(tip) => {
				let json = serde_json::to_string(&tip)
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
		println!("foofoofoo");
		let ref id = req.extensions.get::<Router>().unwrap().find("id").unwrap_or("/");
		println!("utxo handler, id - {:?}", id);
		Ok(Response::with((status::Ok, *id)))
	}
}
