//! The Simplicity verifier of the `mul` guest as a Liquid output, and its spend, checked
//! locally as a node would (feature `simplicity`; no network).

#![cfg(feature = "simplicity")]

use std::str::FromStr;

use bpvm_emu::{Image, IoKind, Machine};
use bpvm_zk::liquid::{self, Contract};
use bulletproofs::curve::{Curve, Secp256k1};
use bulletproofs::simplicity::lang::elements::secp256k1_zkp::Secp256k1 as Ctx;
use bulletproofs::simplicity::lang::elements::{confidential, encode, AddressParams, AssetId, BlockHash, OutPoint, Transaction, TxOut, Txid};
use bulletproofs::simplicity::{sighash_of, SimplicityVerifier};

type K = <Secp256k1 as Curve>::Scalar;

/// The `mul` guest's statement and witness for `a · b`, its inputs committed with blindings 2, 3.
fn mul_statement() -> Option<(bpvm_zk::Statement<Secp256k1>, bpvm_zk::Witness<K>)> {
    let bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/mul/mul.elf")).ok()?;
    let mut img = Image::from_elf(&bytes).unwrap();
    let mut io = bpvm_zk::IoSpec::<K> { private_in: vec![], private_out: vec![], public_out: vec![] };
    let mut blind = 1u64;
    for var in img.io.clone() {
        let v = match var.name.as_str() {
            "a" => vec![100_003],
            "b" => vec![70_001],
            _ => vec![],
        };
        for (addr, w) in var.to_words(&v) {
            img.data.insert(addr, w);
        }
        for i in 0..var.count {
            blind += 1;
            match var.kind {
                IoKind::PrivateInput => io.private_in.push((var.words(i), K::from(blind))),
                IoKind::PrivateOutput => io.private_out.push((var.words(i), K::from(blind))),
                IoKind::PublicOutput => io.public_out.extend(var.words(i)),
                IoKind::PublicInput => {}
            }
        }
    }
    let trace = Machine::from_image(&img).run(1 << 20).unwrap();
    Some(bpvm_zk::witness_with_io::<Secp256k1>(&img, &trace, &io).unwrap())
}

fn funding(contract: &Contract, value: u64) -> (OutPoint, TxOut) {
    let asset = AssetId::from_str(liquid::TESTNET_POLICY_ASSET).unwrap();
    let txid = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
    let utxo = TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey: contract.script_pubkey(),
        witness: Default::default(),
    };
    (OutPoint::new(txid, 0), utxo)
}

/// The address commits to the verifier's leaf: the control block opens the output key to it.
#[test]
fn the_address_commits_to_the_verifier() {
    let Some((st, _)) = mul_statement() else { return };
    let sv = bpvm_zk::vm::simplicity::compile(&st).unwrap();
    let contract = Contract::new(sv.cmr());
    let address = contract.address(&AddressParams::LIQUID_TESTNET);
    let output_key = match address.payload {
        bulletproofs::simplicity::lang::elements::address::Payload::WitnessProgram { version, ref program } => {
            assert_eq!(version.to_u8(), 1, "segwit v1 (Taproot)");
            bulletproofs::simplicity::lang::elements::secp256k1_zkp::XOnlyPublicKey::from_slice(program).unwrap()
        }
        _ => panic!("not a witness program: {address}"),
    };
    let output_key = bulletproofs::simplicity::lang::elements::schnorr::TweakedPublicKey::new(output_key);
    assert!(contract.control_block.verify_taproot_commitment(&Ctx::verification_only(), &output_key, &contract.leaf));
    assert!(address.blinding_pubkey.is_none(), "unconfidential");
    println!("contract {address} (CMR {})", sv.cmr());
}

/// A full spend, run as a node would: the honest proof is accepted within the budget and a
/// standard transaction; a proof made for another transaction is rejected.
#[test]
fn the_verifier_spends_its_output() {
    let Some((st, wit)) = mul_statement() else { return };
    let sv: SimplicityVerifier = bpvm_zk::vm::simplicity::compile(&st).unwrap();
    let contract = Contract::new(sv.cmr());
    let (prevout, utxo) = funding(&contract, 100_000);
    let genesis = BlockHash::from_str("a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1").unwrap();
    let mut tx = liquid::spending_tx(prevout, &utxo, contract.script_pubkey(), 10_000).unwrap();
    let env = liquid::env(&tx, &utxo, &contract, genesis);
    let (proof, _) = bpvm_zk::vm::simplicity::prove(&st, &wit, &sighash_of(&env)).unwrap();
    let spend = sv.spend(&sv.witness(&proof).unwrap(), &env).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(spend.report.cost_mwu <= spend.report.budget_mwu, "{:?}", spend.report);
    liquid::set_witness(&mut tx, &contract, &spend);
    let weight = tx.weight();
    assert!(weight <= liquid::MAX_STANDARD_WEIGHT, "weight {weight}");
    let bytes = encode::serialize(&tx);
    let back: Transaction = encode::deserialize(&bytes).unwrap();
    assert_eq!(back, tx);
    println!("spend: weight {weight} WU, {} B, cost {} of budget {} mWU", bytes.len(), spend.report.cost_mwu, spend.report.budget_mwu);

    // the same proof does not verify for a transaction with another fee
    let other = liquid::spending_tx(prevout, &utxo, contract.script_pubkey(), 10_001).unwrap();
    let other_env = liquid::env(&other, &utxo, &contract, genesis);
    assert!(sv.spend(&sv.witness(&proof).unwrap(), &other_env).is_err());
}
