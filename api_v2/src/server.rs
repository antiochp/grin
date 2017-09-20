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


use std::sync::{Arc, RwLock};
use std::thread;

use chain;
use core::core;
use core::ser;
use pool;

extern crate iron;
extern crate router;
extern crate hyper;

use types::Error;
use handlers::*;

use hyper::mime::*;
use iron::prelude::*;
use iron::Handler;
use iron::status;
use router::Router;
use serde_json;


pub fn start_rest_apis<T>(
	addr: String,
	chain: Arc<chain::Chain>,
	tx_pool: Arc<RwLock<pool::TransactionPool<T>>>
)
	where T: pool::BlockChain + Clone + Send + Sync + 'static
{
	thread::spawn(move || { _start_rest_apis(addr, chain, tx_pool) });
}

fn _start_rest_apis<T>(
	addr: String,
	chain: Arc<chain::Chain>,
	tx_pool: Arc<RwLock<pool::TransactionPool<T>>>
)
	where T: pool::BlockChain + Clone + Send + Sync + 'static
{
	let router = router!(
		chain_index: get "/v1/chain" => ChainHandler{chain: chain.clone()},
		utxo_index: get "/v1/chain/utxo" => UtxoHandler{chain: chain.clone()},
		utxo_get: get "/v1/chain/utxo/:id" => UtxoHandler{chain: chain.clone()},
		pool_index: get "/v1/pool" => PoolInfoHandler{tx_pool: tx_pool.clone()},
		pool_push: post "/v1/pool/push" => PoolPushHandler{tx_pool: tx_pool.clone()},
	);

	Iron::new(router).http(addr).unwrap();
}
