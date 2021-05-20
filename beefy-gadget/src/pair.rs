// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use codec::Codec;
use sp_core::{ecdsa, keccak_256};
use std::fmt::Debug;

/// BEEFY pair trait object
///
/// A BEEFY pair allows us to keep the BEEFY public interface generic regarding
/// the crypto key pair used while still be able to introduce specific behaviour
/// for a given concrete crypto key pair (like ECDSA).
pub(crate) trait BeefyPair<S>
where
	S: Clone + Codec + Debug + PartialEq,
{
	/// Sign `message`
	fn sign(&self, message: &[u8]) -> S;
}

impl BeefyPair<ecdsa::Signature> for ecdsa::Pair {
	fn sign(&self, message: &[u8]) -> ecdsa::Signature {
		let hash = keccak_256(message);
		self.sign_prehashed(&hash)
	}
}

#[cfg(test)]
mod tests {
	use super::BeefyPair;
	use sp_core::{ecdsa, keccak_256, Pair};

	#[test]
	fn beefy_pair_works() {
		let msg = b"this is a beefy commitment";
		let (pair, _, _) = ecdsa::Pair::generate_with_phrase(Some("password"));

		let beefy_pair = Box::new(pair.clone()) as Box<dyn BeefyPair<ecdsa::Signature>>;

		let sig1 = beefy_pair.sign(msg);
		let sig2 = pair.sign_prehashed(&keccak_256(msg));

		assert_eq!(sig1, sig2);
	}
}
