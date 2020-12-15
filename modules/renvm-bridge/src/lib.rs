#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Encode, Decode, HasCompact};
use frame_support::{Parameter, decl_error, decl_event, decl_module, decl_storage, ensure, traits::{Get, EnsureOrigin}};
use frame_system::{self as system, ensure_none, ensure_signed, RawOrigin};
use sp_core::ecdsa;
use sp_io::{crypto::secp256k1_ecdsa_recover, hashing::keccak_256};
use sp_runtime::{traits::{Member, AtLeast32Bit, AtLeast32BitUnsigned},
	transaction_validity::{
		InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity, ValidTransaction,
	},
	DispatchResult,
};
use sp_std::vec::Vec;

use sp_runtime::ModuleId;
use sp_runtime::traits::AccountIdConversion;
use sp_runtime::traits::StaticLookup;
// use frame_system::Module;




#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

type EcdsaSignature = ecdsa::Signature;
type DestAddress = Vec<u8>;

pub trait Config: frame_system::Config + pallet_assets::Config {
	type Event: From<Event<Self>> + Into<<Self as system::Config>::Event>;
	type UnsignedPriority: Get<TransactionPriority>;
	type RenVMTokenIdType: Member + Parameter + AtLeast32BitUnsigned + Default + Copy + HasCompact;
	type ControllerOrigin: EnsureOrigin<Self::Origin>; //Tmp config with EnsureRoot<AccountId>
	type ModuleId: Get<ModuleId>;
}



	type Balance<T>= <T as pallet_assets::Config>::Balance;
	type AssetIdType<T>= <T as pallet_assets::Config>::AssetId;

// struct RenTokenInfo
// ren_token_name string
// ren_token_asset_id how our assets pallets identifies this token, bounds same as the ones for asset
// ren_token_id What ren uses to identify this token on this chain (unique across chains and tokens)
// ren_token_pub_key The Pub key used to check the signature against.
// ren_token_proof proof of this token being registered on the RenVM, legitimizing and enabling stuff like recourse if burnAndRelease fails
// ren_token_mint_enabled,ren_token_burn_enabled to enable/disable currency, instead of delete; you probably do not want to overwrite a token anyway.
// ren_token_mint_fee, ren_token_burn_fee perentage fee on mint and burn
// ren_token_min_req min balance required below which assets will be lost and account may be removed

#[derive(Encode,Decode, Clone, PartialEq, Eq, Debug, Default)]
pub struct RenTokenInfo<RenVMTokenIdType, AssetIdType, Balance>//,RenTokenProofData>
	{
	ren_token_id: RenVMTokenIdType,
	ren_token_asset_id: AssetIdType,
	ren_token_name: Vec<u8>, // TODO: Max length
	ren_token_renvm_id: [u8; 32],
	ren_token_pub_key: [u8; 20],
	// ren_token_proof: Vec<RenTokenProofData>,
	ren_token_mint_enabled: bool,
	ren_token_burn_enabled: bool,
	// ren_token_mint_fee: ,
	// ren_token_burn_fee: ,
	ren_token_min_req: Balance,
}

// #[derive(Encode,Decode, Clone, PartialEq, Eq, Debug, Default)]
// pub struct RenTokenProofData{
// }

type RenTokenInfoType<T> = RenTokenInfo<<T as Config>::RenVMTokenIdType,AssetIdType<T>,Balance<T>>;


decl_storage! {
	trait Store for Module<T: Config> as Template {
		/// Signature blacklist. This is required to prevent double claim.
		Signatures get(fn signatures): map hasher(opaque_twox_256) EcdsaSignature => Option<()>;

		/// Record burn event
		// BurnEvents get(fn burn_events): map hasher(twox_64_concat) u32 => Option<(T::BlockNumber, DestAddress, Balance)>;
		// /// Next burn event ID
		// NextBurnEventId get(fn next_burn_event_id): u128;

		RenTokenRegistry get(fn ren_token_registry): map hasher(blake2_128_concat) <T as Config>::RenVMTokenIdType => RenTokenInfoType<T>;

	}
}

decl_event!(
	pub enum Event<T> where RenVMTokenIdType = <T as Config>::RenVMTokenIdType
	{
		// /// Asset minted. \[owner, amount\]
		// Minted(AccountId, Balance),
		// /// Asset burnt in this chain \[owner, dest, amount\]
		// Burnt(AccountId, DestAddress, Balance),
		/// Token Added
		RenTokenAdded(RenVMTokenIdType),
		/// Token Info Updated
		RenTokenUpdated(RenVMTokenIdType),
	}
);

decl_error! {
	pub enum Error for Module<T: Config> {
		/// The mint signature is invalid.
		InvalidMintSignature,
		/// The mint signature has already been used.
		SignatureAlreadyUsed,
		/// Burn ID overflow.
		BurnIdOverflow,
		/// RenTokenAlready Exists
		RenTokenAlreadyExists,
		/// No token with this ren_token_id found
		RenTokenNotFound,

		MintFailed,
	}
}

decl_module! {
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		#[weight = 10_000]
		fn add_ren_token(
			origin,
			_ren_token_id: T::RenVMTokenIdType,
			_ren_token_asset_id: AssetIdType<T>,
			_ren_token_name: Vec<u8>,
			_ren_token_renvm_id: [u8; 32],
			_ren_token_pub_key: [u8; 20],
			_ren_token_mint_enabled: bool,
			_ren_token_burn_enabled: bool,
			_ren_token_min_req: Balance<T>,
		) -> DispatchResult
		{
			T::ControllerOrigin::ensure_origin(origin)?;

			ensure!(!<RenTokenRegistry<T>>::contains_key(&_ren_token_id), Error::<T>::RenTokenAlreadyExists);

			let pallet_account = Self::account_id();

			pallet_assets::Module::<T>::force_create(
				RawOrigin::Root.into(),
				_ren_token_asset_id.into(),
				T::Lookup::unlookup(pallet_account),
				u32::MAX,
				_ren_token_min_req.into(),
			).or_else(|_|{Err(Error::<T>::MintFailed)})?;

			let _ren_token_info = RenTokenInfo{
				ren_token_id: _ren_token_id,
				ren_token_asset_id: _ren_token_asset_id,
				ren_token_name: _ren_token_name,
				ren_token_renvm_id: _ren_token_renvm_id,
				ren_token_pub_key: _ren_token_pub_key,
				ren_token_mint_enabled: _ren_token_mint_enabled,
				ren_token_burn_enabled: _ren_token_burn_enabled,
				ren_token_min_req: _ren_token_min_req,
			};

			// use try_mutate_exists for atomicity
			RenTokenRegistry::<T>::insert(&_ren_token_id,_ren_token_info);

			Self::deposit_event(RawEvent::RenTokenAdded(_ren_token_id));
			Ok(())
		}


		// #[weight = 10_000]
		// fn mint(
		// 	origin,
		// 	who: T::AccountId,
		// 	p_hash: [u8; 32],
		// 	#[compact] amount: Balance,
		// 	n_hash: [u8; 32],
		// 	sig: EcdsaSignature,
		// ) {
		// 	ensure_none(origin)?;
		// 	Self::do_mint(who, amount, sig)?;
		// }
		//
		// /// Allow a user to burn assets.
		// #[weight = 10_000]
		// fn burn(
		// 	origin,
		// 	to: DestAddress,
		// 	#[compact] amount: Balance,
		// ) {
		// 	let sender = ensure_signed(origin)?;
		//
		// 	NextBurnEventId::try_mutate(|id| -> DispatchResult {
		// 		let this_id = *id;
		// 		*id = id.checked_add(1).ok_or(Error::<T>::BurnIdOverflow)?;
		//
		// 		T::Currency::withdraw(&sender, amount)?;
		// 		BurnEvents::<T>::insert(this_id, (frame_system::Module::<T>::block_number(), &to, amount));
		// 		Self::deposit_event(RawEvent::Burnt(sender, to, amount));
		//
		// 		Ok(())
		// 	})?;
		// }
	}
}

impl<T: Config> Module<T> {
	// fn do_mint(sender: T::AccountId, amount: Balance, sig: EcdsaSignature) -> DispatchResult {
	// 	T::Currency::deposit(&sender, amount)?;
	// 	Signatures::insert(&sig, ());
	//
	// 	Self::deposit_event(RawEvent::Minted(sender, amount));
	// 	Ok(())
	// }
	//

	/// The account ID that holds the pallet's accumulated funds on pallet-assets; mostly fees for now, maybe for loss of exsistential deposit later.
    pub fn account_id() -> T::AccountId {
        T::ModuleId::get().into_account()
    }

	// // ABI-encode the values for creating the signature hash.
	// fn signable_message(p_hash: &[u8; 32], amount: u128, to: &[u8], n_hash: &[u8; 32], token: &[u8; 32]) -> Vec<u8> {
	// 	// p_hash ++ amount ++ token ++ to ++ n_hash
	// 	let length = 32 + 32 + 32 + 32 + 32;
	// 	let mut v = Vec::with_capacity(length);
	// 	v.extend_from_slice(&p_hash[..]);
	// 	v.extend_from_slice(&[0u8; 16][..]);
	// 	v.extend_from_slice(&amount.to_be_bytes()[..]);
	// 	v.extend_from_slice(&token[..]);
	// 	v.extend_from_slice(to);
	// 	v.extend_from_slice(&n_hash[..]);
	// 	v
	// }
	//
	// // Verify that the signature has been signed by RenVM.
	// fn verify_signature(
	// 	p_hash: &[u8; 32],
	// 	amount: u128,
	// 	to: &[u8],
	// 	n_hash: &[u8; 32],
	// 	sig: &[u8; 65],
	// ) -> DispatchResult {
	// 	let ren_btc_identifier = T::CurrencyIdentifier::get();
	//
	// 	let signed_message_hash = keccak_256(&Self::signable_message(p_hash, amount, to, n_hash, &ren_btc_identifier));
	// 	let recoverd =
	// 		secp256k1_ecdsa_recover(&sig, &signed_message_hash).map_err(|_| Error::<T>::InvalidMintSignature)?;
	// 	let addr = &keccak_256(&recoverd)[12..];
	//
	// 	ensure!(addr == T::PublicKey::get(), Error::<T>::InvalidMintSignature);
	//
	// 	Ok(())
	// }
}

// #[allow(deprecated)]
// impl<T: Config> frame_support::unsigned::ValidateUnsigned for Module<T> {
	// type Call = Call<T>;
	//
	// fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
	// 	if let Call::mint(who, p_hash, amount, n_hash, sig) = call {
	// 		// check if already exists
	// 		if Signatures::contains_key(&sig) {
	// 			return InvalidTransaction::Stale.into();
	// 		}
	//
	// 		let verify_result = Encode::using_encoded(&who, |encoded| -> DispatchResult {
	// 			Self::verify_signature(&p_hash, *amount, encoded, &n_hash, &sig.0)
	// 		});
	//
	// 		// verify signature
	// 		if verify_result.is_err() {
	// 			return InvalidTransaction::BadProof.into();
	// 		}
	//
	// 		ValidTransaction::with_tag_prefix("renvm-bridge")
	// 			.priority(T::UnsignedPriority::get())
	// 			.and_provides(sig)
	// 			.longevity(64_u64)
	// 			.propagate(true)
	// 			.build()
	// 	} else {
	// 		InvalidTransaction::Call.into()
	// 	}
	// }
// }
