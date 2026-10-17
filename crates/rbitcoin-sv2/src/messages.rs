//! Job-validation extension to TDP (`docs/sv2-job-validation.md` §3–5):
//! the `SetupConnection` flag, the `ProposeTemplate` request and its two
//! replies, and the `ProvideMissingTransactions` pair a Job Declarator
//! Server relays between this TP and its JDC.

use binary_sv2::{Deserialize, Seq064K, Serialize, Str0255, B016M, B064K, U256};

/// `SetupConnection.flags` bit 0: the client intends to send
/// [`ProposeTemplate`]. The only TDP flag this TP accepts.
pub(crate) const REQUIRES_JOB_VALIDATION: u32 = 1 << 0;

pub(crate) const MESSAGE_TYPE_PROPOSE_TEMPLATE: u8 = 0x77;
pub(crate) const MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS: u8 = 0x78;
pub(crate) const MESSAGE_TYPE_PROPOSE_TEMPLATE_SUCCESS: u8 = 0x79;
pub(crate) const MESSAGE_TYPE_PROPOSE_TEMPLATE_ERROR: u8 = 0x7a;
pub(crate) const MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS: u8 = 0x7b;

/// Client → TP: is this custom job a consensus-valid block on the TP tip?
/// The `DeclareMiningJob` subset a node needs, relayed unchanged: the
/// coinbase split around the extranonce and the declared wtxids. Carries no
/// transactions; the TP asks for the ones it lacks with
/// [`ProvideMissingTransactions`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProposeTemplate<'decoder> {
    pub request_id: u32,
    pub version: u32,
    pub coinbase_tx_prefix: B064K<'decoder>,
    pub coinbase_tx_suffix: B064K<'decoder>,
    pub wtxid_list: Seq064K<'decoder, U256<'decoder>>,
    /// Opaque to the TP (TDP 7.6 semantics belong to the Pool).
    pub excess_data: B064K<'decoder>,
}

/// TP → client: 0-indexed positions in `wtxid_list` the TP cannot resolve.
/// The layout of JDP 6.4.7, so a JDS copies the payload to its JDC.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvideMissingTransactions<'decoder> {
    pub request_id: u32,
    pub unknown_tx_position_list: Seq064K<'decoder, u16>,
}

/// Client → TP: the transactions a [`ProvideMissingTransactions`] asked
/// for, in that order. The layout of JDP 6.4.8, copied from the JDC.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvideMissingTransactionsSuccess<'decoder> {
    pub request_id: u32,
    pub transaction_list: Seq064K<'decoder, B016M<'decoder>>,
}

/// TP → client: the job is valid on the tip `prev_hash` and retained under
/// `template_id`, which shares the `NewTemplate.template_id` namespace.
/// `fees` is the fee total of the declared transactions as the node's
/// validation computed it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProposeTemplateSuccess<'decoder> {
    pub request_id: u32,
    pub template_id: u64,
    pub prev_hash: U256<'decoder>,
    pub fees: u64,
}

/// TP → client: the job was not validated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProposeTemplateError<'decoder> {
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
        let (prefix, suffix, tx, details) =
            ([0xc0u8; 50], [0xc1u8; 100], [0xeeu8; 300], [1u8, 2, 3]);
        let mut bytes = Vec::new();
        round_trip(
            ProposeTemplate {
                request_id: 7,
                version: 0x2000_0000,
                coinbase_tx_prefix: B064K::try_from(&prefix[..]).unwrap(),
                coinbase_tx_suffix: B064K::try_from(&suffix[..]).unwrap(),
                wtxid_list: Seq064K::new(vec![U256::from(&h2), U256::from(&h3)]).unwrap(),
                excess_data: B064K::try_from(&details[..]).unwrap(),
            },
            &mut bytes,
        );
        let mut bytes = Vec::new();
        round_trip(
            ProvideMissingTransactions {
                request_id: 7,
                unknown_tx_position_list: Seq064K::new(vec![0u16, 5, u16::MAX]).unwrap(),
            },
            &mut bytes,
        );
        let mut bytes = Vec::new();
        round_trip(
            ProvideMissingTransactionsSuccess {
                request_id: 7,
                transaction_list: Seq064K::new(vec![B016M::try_from(&tx[..]).unwrap()]).unwrap(),
            },
            &mut bytes,
        );
        let mut bytes = Vec::new();
        round_trip(
            ProposeTemplateSuccess {
                request_id: 7,
                template_id: u64::MAX,
                prev_hash: U256::from(&h1),
                fees: 12_345,
            },
            &mut bytes,
        );
        let mut bytes = Vec::new();
        round_trip(
            ProposeTemplateError {
                request_id: 7,
                error_code: Str0255::try_from("bad-cb-decode").unwrap(),
                error_details: B064K::try_from(&details[..]).unwrap(),
            },
            &mut bytes,
        );
    }
}
