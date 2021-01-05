
//! Autogenerated weights for edge_ren
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 2.0.0
//! DATE: 2021-01-05, STEPS: [2, ], REPEAT: 2, LOW RANGE: [], HIGH RANGE: []
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
// validate_and_mint
// --steps
// 2
// --repeat
// 2
// --output
// ./edge_bench_2/edge_ren_1.rs
// --raw


#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for edge_ren.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> edge_ren::WeightInfo for WeightInfo<T> {
	fn validate_and_mint(z: u32, ) -> Weight {
		(243_572_000 as Weight)
			// Standard Error: 0
			.saturating_add((16_000 as Weight).saturating_mul(z as Weight))
			.saturating_add(T::DbWeight::get().reads(7 as Weight))
			.saturating_add(T::DbWeight::get().writes(4 as Weight))
	}
}