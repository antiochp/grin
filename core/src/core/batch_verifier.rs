// Copyright 2018 The Grin Developers
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

//! A trait for something that verifies other things.
//! We can use this to pass a "caching verifier" into the block validation processing.

use core::{Output, TxKernel};
use util::secp;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
	Rangeproof,
	KernelSignature,
	Secp(secp::Error),
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

pub trait BatchVerifier {
	fn verify_rangeproofs(&self, items: &Vec<Output>) -> Result<(), Error>;

	fn verify_kernel_signatures(&self, items: &Vec<TxKernel>) -> Result<(), Error>;
}
