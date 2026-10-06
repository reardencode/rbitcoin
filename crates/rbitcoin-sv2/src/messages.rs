//! Job-validation extension to TDP (`docs/sv2-job-validation-draft.md` §3–5):
//! the `SetupConnection` flag and the four `ValidateCustomJob` messages a
//! Job Declarator Server uses to have this TP check a custom job.

use binary_sv2::{Deserialize, Seq064K, Serialize, Str0255, B016M, B064K, U256};

/// `SetupConnection.flags` bit 0: the client intends to send
/// [`ValidateCustomJob`]. The only TDP flag this TP accepts.
pub const REQUIRES_JOB_VALIDATION: u32 = 1 << 0;

pub const MESSAGE_TYPE_VALIDATE_CUSTOM_JOB: u8 = 0x77;
pub const MESSAGE_TYPE_VALIDATE_CUSTOM_JOB_MISSING_TRANSACTIONS: u8 = 0x78;
pub const MESSAGE_TYPE_VALIDATE_CUSTOM_JOB_SUCCESS: u8 = 0x79;
pub const MESSAGE_TYPE_VALIDATE_CUSTOM_JOB_ERROR: u8 = 0x7a;

/// Client → TP: is this custom job a consensus-valid block on the TP tip?
/// `transaction_list` carries the txs a prior
/// [`ValidateCustomJobMissingTransactions`] asked for, in that order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidateCustomJob<'decoder> {
    pub request_id: u32,
    pub prev_hash: U256<'decoder>,
    pub version: u32,
    pub coinbase_tx: B064K<'decoder>,
    pub wtxid_list: Seq064K<'decoder, U256<'decoder>>,
    pub transaction_list: Seq064K<'decoder, B016M<'decoder>>,
}

/// TP → client: 0-indexed positions in `wtxid_list` the TP cannot resolve.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidateCustomJobMissingTransactions<'decoder> {
    pub request_id: u32,
    pub unknown_tx_position_list: Seq064K<'decoder, u16>,
}

/// TP → client: the job is valid and retained under `template_id`, which
/// shares the `NewTemplate.template_id` namespace.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidateCustomJobSuccess {
    pub request_id: u32,
    pub template_id: u64,
    pub fees: u64,
}

/// TP → client: the job was not validated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidateCustomJobError<'decoder> {
    pub request_id: u32,
    pub error_code: Str0255<'decoder>,
    pub error_details: B064K<'decoder>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binary_sv2::{Seq064K, Str0255, B016M, B064K, U256};
    use std::fmt::Debug;

    /// Encode with the codec `NoiseWriter::send` frames and decode with the
    /// one `Session::on_frame` uses.
    fn round_trip<'a, T>(msg: T, bytes: &'a mut Vec<u8>)
    where
        T: Clone
            + PartialEq
            + Debug
            + binary_sv2::Serialize
            + binary_sv2::GetSize
            + binary_sv2::Deserialize<'a>,
    {
        *bytes = binary_sv2::to_bytes(msg.clone()).expect("encode");
        let back: T = binary_sv2::from_bytes(bytes).expect("decode");
        assert_eq!(back, msg);
    }

    #[test]
    fn job_validation_messages_round_trip() {
        let (h1, h2, h3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let (coinbase, tx, details) = ([0xc0u8; 100], [0xeeu8; 300], [1u8, 2, 3]);
        let mut bytes = Vec::new();
        round_trip(
            ValidateCustomJob {
                request_id: 7,
                prev_hash: U256::from(&h1),
                version: 0x2000_0000,
                coinbase_tx: B064K::try_from(&coinbase[..]).unwrap(),
                wtxid_list: Seq064K::new(vec![U256::from(&h2), U256::from(&h3)]).unwrap(),
                transaction_list: Seq064K::new(vec![B016M::try_from(&tx[..]).unwrap()]).unwrap(),
            },
            &mut bytes,
        );
        let mut bytes = Vec::new();
        round_trip(
            ValidateCustomJobMissingTransactions {
                request_id: 7,
                unknown_tx_position_list: Seq064K::new(vec![0u16, 5, u16::MAX]).unwrap(),
            },
            &mut bytes,
        );
        let mut bytes = Vec::new();
        round_trip(
            ValidateCustomJobSuccess {
                request_id: 7,
                template_id: u64::MAX,
                fees: 12_345,
            },
            &mut bytes,
        );
        let mut bytes = Vec::new();
        round_trip(
            ValidateCustomJobError {
                request_id: 7,
                error_code: Str0255::try_from("stale-prevhash").unwrap(),
                error_details: B064K::try_from(&details[..]).unwrap(),
            },
            &mut bytes,
        );
    }
}
