//! Liquid (feature `simplicity`): the Simplicity verifier of a statement as a Taproot output,
//! and the transaction that spends it with a proof.
//!
//! The output commits to one Taproot leaf, the verifier's CMR with Simplicity's leaf version
//! (0xbe), under BIP 341's unspendable internal key, so it can only be spent by running the
//! verifier. The spend's witness stack is `[witness, program, cmr, control block]`; the proof is
//! bound to the spending transaction through `jet_sig_all_hash`, so it is made after the
//! transaction is built (and before its witness is set, which the hash does not cover).

use std::sync::Arc;

use bulletproofs::simplicity::lang::elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use bulletproofs::simplicity::lang::elements::taproot::{ControlBlock, TaprootBuilder};
use bulletproofs::simplicity::lang::elements::{
    confidential, Address, AddressParams, AssetId, AssetIssuance, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness, TxOut,
};
use bulletproofs::simplicity::lang::jet::elements::{ElementsEnv, ElementsUtxo};
use bulletproofs::simplicity::lang::{leaf_version, Cmr};
use bulletproofs::simplicity::{Env, Spend};

/// BIP 341's point H (x-only): nobody knows its discrete logarithm, so the key path is closed.
const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// L-BTC on Liquid testnet.
pub const TESTNET_POLICY_ASSET: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

/// The standard transaction weight limit (Elements policy, as Bitcoin's).
pub const MAX_STANDARD_WEIGHT: usize = 400_000;

/// A Taproot output with the verifier as its only leaf.
#[derive(Clone, Debug)]
pub struct Contract {
    /// The verifier's commitment Merkle root.
    pub cmr: Cmr,
    /// The leaf script: the CMR's 32 bytes.
    pub leaf: Script,
    /// The control block of the leaf.
    pub control_block: ControlBlock,
    internal_key: XOnlyPublicKey,
    merkle_root: Option<bulletproofs::simplicity::lang::elements::taproot::TapNodeHash>,
}

impl Contract {
    /// The output of the verifier with commitment Merkle root `cmr`.
    pub fn new(cmr: Cmr) -> Self {
        let secp = Secp256k1::verification_only();
        let internal_key = XOnlyPublicKey::from_slice(&NUMS).expect("H is a point");
        let leaf = Script::from(cmr.as_ref().to_vec());
        let info = TaprootBuilder::new()
            .add_leaf_with_ver(0, leaf.clone(), leaf_version())
            .expect("one leaf")
            .finalize(&secp, internal_key)
            .expect("a tree of one leaf");
        let control_block = info.control_block(&(leaf.clone(), leaf_version())).expect("the leaf is in the tree");
        Contract { cmr, leaf, control_block, internal_key, merkle_root: info.merkle_root() }
    }

    /// The (unconfidential) address of the output on the network of `params`.
    pub fn address(&self, params: &'static AddressParams) -> Address {
        Address::p2tr(&Secp256k1::verification_only(), self.internal_key, self.merkle_root, None, params)
    }

    /// The output's script.
    pub fn script_pubkey(&self) -> Script {
        self.address(&AddressParams::LIQUID_TESTNET).script_pubkey()
    }
}

/// The explicit value and asset of `utxo`; an error for a confidential output (the verifier's
/// address is unconfidential, so funds sent to it are explicit).
pub fn explicit(utxo: &TxOut) -> Result<(u64, AssetId), String> {
    match (utxo.value, utxo.asset) {
        (confidential::Value::Explicit(v), confidential::Asset::Explicit(a)) => Ok((v, a)),
        _ => Err("the output is confidential; send explicit (unconfidential) funds to the contract".into()),
    }
}

/// A transaction that spends `prevout`, the contract's output `utxo`, to `to` (its value minus
/// `fee`) with an explicit fee output; no witness yet.
pub fn spending_tx(prevout: OutPoint, utxo: &TxOut, to: Script, fee: u64) -> Result<Transaction, String> {
    let (value, asset) = explicit(utxo)?;
    let out = value.checked_sub(fee).filter(|v| *v > 0).ok_or(format!("the output holds {value}, not more than the fee {fee}"))?;
    Ok(Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: AssetIssuance::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![
            TxOut { asset: confidential::Asset::Explicit(asset), value: confidential::Value::Explicit(out), nonce: confidential::Nonce::Null, script_pubkey: to, witness: Default::default() },
            TxOut::new_fee(fee, asset),
        ],
    })
}

/// The environment the verifier runs in when `tx` spends `utxo` (input 0) on the chain with
/// genesis block `genesis`.
pub fn env(tx: &Transaction, utxo: &TxOut, contract: &Contract, genesis: BlockHash) -> Env {
    let utxos = vec![ElementsUtxo { script_pubkey: utxo.script_pubkey.clone(), asset: utxo.asset, value: utxo.value }];
    ElementsEnv::new(Arc::new(tx.clone()), utxos, 0, contract.cmr, contract.control_block.clone(), None, genesis)
}

/// Set input 0's witness stack to `[witness, program, cmr, control block]`.
pub fn set_witness(tx: &mut Transaction, contract: &Contract, spend: &Spend) {
    let stack = vec![spend.witness.clone(), spend.program.clone(), contract.cmr.as_ref().to_vec(), contract.control_block.serialize()];
    tx.input[0].witness.script_witness = stack.into();
}

/// The fee for `weight` at `sat_per_vb` (rounded up, in satoshi).
pub fn fee_for(weight: usize, sat_per_vb: f64) -> u64 {
    ((weight as f64 / 4.0) * sat_per_vb).ceil() as u64
}
