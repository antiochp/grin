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

//! Provides the JSON/HTTP API for wallets to receive payments. Because
//! receiving money in MimbleWimble requires an interactive exchange, a
//! wallet server that's running at all time is required in many cases.
//!
//! The API looks like this:
//!
//! POST /v1/wallet/receive
//! > {
//! >   "amount": 10,
//! >   "blind_sum": "a12b7f...",
//! >   "tx": "f083de...",
//! > }
//!
//! < {
//! <   "tx": "f083de...",
//! <   "status": "ok"
//! < }
//!
//! POST /v1/wallet/finalize
//! > {
//! >   "tx": "f083de...",
//! > }
//!
//! POST /v1/wallet/receive_coinbase
//! > {
//! >   "amount": 1,
//! > }
//!
//! < {
//! <   "output": "8a90bc...",
//! <   "kernel": "f083de...",
//! < }
//!
//! Note that while at this point the finalize call is completely unecessary, a
//! double-exchange will be required as soon as we support Schnorr signatures.
//! So we may as well have it in place already.


use std::sync::{Arc, RwLock};
use std::thread;

extern crate iron;
extern crate router;
extern crate hyper;

use types::*;
use handlers::*;
use extkey::ExtendedKey;

use hyper::mime::*;
use iron::prelude::*;
use iron::Handler;
use iron::status;
use router::Router;
use serde_json;


pub fn start_rest_apis(config: &WalletConfig, ext_key: &ExtendedKey) {
	let router = router!(
		receive_coinbase: post("/v1/receive/coinbase") =>
			CoinbaseHandler{ ext_key: ext_key.clone(), config: config.clone() },
		receive_json_tx: post("/v1/receive/receive_json_tx") =>
			JsonTxHandler{ ext_key: ext_key.clone(), config: config.clone() },
	);

	Iron::new(router).http(config.clone().api_http_addr).unwrap();
}
