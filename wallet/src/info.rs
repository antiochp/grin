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

use api;
use core::core::Output;
use secp::{self, pedersen};
use util;

use checker;
use extkey::ExtendedKey;
use types::{WalletConfig, OutputStatus, WalletData};

pub fn info(config: &WalletConfig, ext_key: &ExtendedKey) {
	println!("about to refresh outputs");
	checker::refresh_outputs(&config, ext_key);

	let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);

	// operate within a lock on wallet data
	let _ = WalletData::with_wallet(&config.data_file_dir, |wallet_data| {

		for out in &mut wallet_data.outputs {
			let key = ext_key.derive(&secp, out.n_child).unwrap();
			let commitment = secp.commit(out.value, key.key).unwrap();

			println!("output - {:?}, {:?}, {:?}, {:?}", key.identifier().fingerprint(), out.n_child, out.status, out.value);
		}
	});
}
