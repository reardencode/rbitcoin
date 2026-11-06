//! Core's transaction and block deserializers where rust-bitcoin's differ.
//!
//! P2P `cmpctblock`, RPC raw transactions, and RPC blocks read bytes the way
//! Core does, so they accept and refuse the same inputs.

use crate::script::interpreter::{MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE_LEGACY};
use bitcoin::consensus::encode::{Decodable, Error, VarInt};
use bitcoin::opcodes::all::OP_NOP10;
use bitcoin::script::Instruction;
use bitcoin::{Block, Script, Transaction};

/// Core `UnserializeTransaction` with witness (`TX_WITH_WITNESS`). Only an
/// empty vin differs from rust-bitcoin: flags 0 leaves vout empty and reads
/// the locktime (Core's null tx, which rust-bitcoin refuses as segwit flag 0),
/// and flag 1 followed by a second empty vin carries no witness, which Core
/// refuses as a superfluous witness record and rust-bitcoin accepts.
pub fn decode_tx_with_witness(d: &mut &[u8]) -> Result<Transaction, Error> {
    if d.get(4..7) == Some(&[0u8, 1, 0][..]) {
        return Err(Error::ParseFailed("superfluous witness record"));
    }
    match take_null_tx(d) {
        Some(tx) => Ok(tx),
        None => Transaction::consensus_decode(d),
    }
}

fn take_null_tx(d: &mut &[u8]) -> Option<Transaction> {
    let (b, rest) = d.split_first_chunk::<10>()?;
    if b[4] != 0 || b[5] != 0 {
        return None;
    }
    let version = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let lock_time = u32::from_le_bytes([b[6], b[7], b[8], b[9]]);
    *d = rest;
    Some(Transaction {
        version: bitcoin::transaction::Version(version),
        lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time),
        input: Vec::new(),
        output: Vec::new(),
    })
}

/// Core `TX_NO_WITNESS`: vin, vout, and locktime, with no marker or flags.
pub fn decode_tx_no_witness(d: &mut &[u8]) -> Result<Transaction, Error> {
    Ok(Transaction {
        version: Decodable::consensus_decode(d)?,
        input: Decodable::consensus_decode(d)?,
        output: Decodable::consensus_decode(d)?,
        lock_time: Decodable::consensus_decode(d)?,
    })
}

/// Core `DecodeTx`. Each allowed form must consume every byte. When both
/// decode, the witness form wins unless only the legacy form's scripts parse.
pub fn decode_tx(bytes: &[u8], try_no_witness: bool, try_witness: bool) -> Option<Transaction> {
    let whole = |decode: fn(&mut &[u8]) -> Result<Transaction, Error>| {
        let mut d = bytes;
        decode(&mut d).ok().filter(|_| d.is_empty())
    };
    let with_witness = if try_witness {
        whole(decode_tx_with_witness)
    } else {
        None
    };
    if with_witness.as_ref().is_some_and(scripts_parse) {
        return with_witness;
    }
    let no_witness = if try_no_witness {
        whole(decode_tx_no_witness)
    } else {
        None
    };
    if no_witness.as_ref().is_some_and(scripts_parse) {
        return no_witness;
    }
    with_witness.or(no_witness)
}

/// Core `CheckTxScriptsSanity`: every output script, and every input script
/// of a non-coinbase, passes [`has_valid_ops`].
fn scripts_parse(tx: &Transaction) -> bool {
    let inputs = tx
        .input
        .iter()
        .filter(|_| !tx.is_coinbase())
        .map(|i| i.script_sig.as_script());
    let outputs = tx.output.iter().map(|o| o.script_pubkey.as_script());
    inputs.chain(outputs).all(has_valid_ops)
}

/// Core `CScript::HasValidOps` and the `MAX_SCRIPT_SIZE` bound.
pub fn has_valid_ops(script: &Script) -> bool {
    script.len() <= MAX_SCRIPT_SIZE_LEGACY
        && script.instructions().all(|ins| match ins {
            Ok(Instruction::PushBytes(push)) => push.len() <= MAX_SCRIPT_ELEMENT_SIZE,
            Ok(Instruction::Op(op)) => op.to_u8() <= OP_NOP10.to_u8(),
            Err(_) => false,
        })
}

/// Core `DecodeHexBlk` after hex: the header, then each transaction as
/// [`decode_tx_with_witness`]. Core never checks that the stream is empty,
/// so bytes after the last transaction are ignored.
pub fn decode_block(mut d: &[u8]) -> Result<Block, Error> {
    let header = Decodable::consensus_decode(&mut d)?;
    let n = VarInt::consensus_decode(&mut d)?.0;
    let mut txdata = Vec::new();
    for _ in 0..n {
        txdata.push(decode_tx_with_witness(&mut d)?);
    }
    Ok(Block { header, txdata })
}
