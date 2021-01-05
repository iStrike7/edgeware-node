
//! Autogenerated weights for edge_ren
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 2.0.0
//! DATE: 2021-01-04, STEPS: [50, ], REPEAT: 20, LOW RANGE: [], HIGH RANGE: []
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("dev"), DB CACHE: 128

// Executed Command:
// ./target/release/edgeware
// benchmark
// --chain
// dev
// --execution=wasm
// --wasm-execution=compiled
// --pallet
// edge_ren
// --extrinsic
// *
// --steps
// 50
// --repeat
// 20
// --output
// .


#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for edge_ren.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> edge_ren::WeightInfo for WeightInfo<T> {
	fn add_ren_token() -> Weight {
		(63_842_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(2 as Weight))
			.saturating_add(T::DbWeight::get().writes(2 as Weight))
	}
	fn update_ren_token() -> Weight {
		(36_525_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(1 as Weight))
			.saturating_add(T::DbWeight::get().writes(1 as Weight))
	}
	fn delete_ren_token(z: u32, ) -> Weight {
		(0 as Weight)
			// Standard Error: 8_000
			.saturating_add((1_643_000 as Weight).saturating_mul(z as Weight))
			.saturating_add(T::DbWeight::get().reads(2 as Weight))
			.saturating_add(T::DbWeight::get().writes(2 as Weight))
			.saturating_add(T::DbWeight::get().writes((1 as Weight).saturating_mul(z as Weight)))
	}
	fn spend_tokens() -> Weight {
		(114_594_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(6 as Weight))
			.saturating_add(T::DbWeight::get().writes(3 as Weight))
	}
	fn validate_and_mint(z: u32, ) -> Weight {
		(395_865_000 as Weight)
			// Standard Error: 0
			.saturating_add((8_000 as Weight).saturating_mul(z as Weight))
			.saturating_add(T::DbWeight::get().reads(7 as Weight))
			.saturating_add(T::DbWeight::get().writes(4 as Weight))
	}
	fn burn() -> Weight {
		(150_700_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(6 as Weight))
			.saturating_add(T::DbWeight::get().writes(5 as Weight))
	}
}