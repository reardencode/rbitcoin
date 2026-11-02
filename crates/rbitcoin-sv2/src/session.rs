//! One TDP session: Noise handshake, `SetupConnection`, then TDP messages.

use crate::job::{self, Proposal, Supplied, Verdict, UNAVAILABLE};
use crate::messages::{
    ProposeTemplateError, ProposeTemplateSuccess, ProvideMissingTransactions,
    ProvideMissingTransactionsSuccess, MESSAGE_TYPE_PROPOSE_TEMPLATE,
    MESSAGE_TYPE_PROPOSE_TEMPLATE_ERROR, MESSAGE_TYPE_PROPOSE_TEMPLATE_SUCCESS,
    MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS, MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
    REQUIRES_JOB_VALIDATION,
};
use crate::template::{self, Bits};
use crate::transport::{Frame, NoiseConn, NoiseWriter};
use crate::Sv2TpStats;
use binary_sv2::{Seq064K, Str0255, B016M, B064K, U256};
use bitcoin::hashes::Hash;
use bitcoin::{block, Block, BlockHash, CompactTarget, Transaction, TxMerkleNode, Witness};
use common_messages_sv2::{
    Protocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
    ERROR_CODE_SETUP_CONNECTION_PROTOCOL_VERSION_MISMATCH,
    ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS,
    ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL, MESSAGE_TYPE_SETUP_CONNECTION,
    MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use noise_sv2::Responder;
use rbitcoin_net::{BlockingRegion, ChainHub};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use template_distribution_sv2::{
    CoinbaseOutputConstraints, RequestTransactionData, RequestTransactionDataError,
    RequestTransactionDataSuccess, SubmitSolution,
    ERROR_CODE_REQUEST_TRANSACTION_DATA_STALE_TEMPLATE_ID,
    ERROR_CODE_REQUEST_TRANSACTION_DATA_TEMPLATE_ID_NOT_FOUND,
    MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, MESSAGE_TYPE_NEW_TEMPLATE,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS, MESSAGE_TYPE_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_SUBMIT_SOLUTION,
};
use tokio::net::TcpStream;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, AcquireError, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

#[doc(hidden)]
pub const TDP_VERSION: u16 = 2;

/// RAM trade (docs/sv2-template-provider.md): each session keeps its
/// templates, so `RequestTransactionData` and `SubmitSolution` do not depend
/// on the mempool still holding their txs. Fee pushes add one per interval
/// on the same tip and a miner may still be on any of them, so the bound is
/// a count, oldest (replaced tips first) dropped. Bodies are the mempool's
/// `Arc`s: a template costs a pointer per tx until its txs leave the pool.
/// Supplied custom-job bodies are private to that job.
#[doc(hidden)]
pub const MAX_RETAINED: usize = 64;

/// The tips this session moved off whose retirement deadline it remembers,
/// so a job that finishes on one of them after the move retires with the
/// templates that were on it. A validation spans a few tip changes at most;
/// an older tip is left for the next tip event to classify.
#[doc(hidden)]
pub const MAX_RETIRED_TIPS: usize = 8;

/// Budgets that replace a still-queued one before it is built. A real client
/// changes its budget minutes apart; past this many inside one cooldown the
/// session is closed so the slot goes back to a real client.
#[doc(hidden)]
pub const MAX_SUPERSEDED_CONSTRAINTS: u32 = 8;

/// When a changed budget rebuilds. `None` means `cooldown` has elapsed and
/// the budget publishes on this message. The node passes
/// [`crate::CONSTRAINTS_COOLDOWN`].
pub fn constraints_rebuild_at(
    built_at: Instant,
    now: Instant,
    cooldown: Duration,
) -> Option<Instant> {
    let at = built_at + cooldown;
    (at > now).then_some(at)
}

/// CPU and RAM trade (CONTRIBUTING 9): a `ProposeTemplate` validation is one
/// full proposal check on a blocking thread holding up to a block of decoded
/// transactions. How many run at once is a listener-wide permit count
/// ([`crate::Sv2TpConfig::validation_permits`]); this session's accepted work
/// waits for a permit in arrival order.
///
/// RAM trade (CONTRIBUTING 9): `ProposeTemplate` and
/// `ProvideMissingTransactions.Success` work a session has accepted and not
/// yet answered, queued and running together, is bounded by this count and
/// by [`MAX_ADMITTED_BYTES`]. A frame past either is answered
/// `job-validation-unavailable` (the IBD gate's code; sv2-tp#137 answers the
/// same at its bound) and the session keeps serving. A JDS declares one job
/// per JDC per tip change, each a few thousand wtxids (~100 KiB), so 16
/// covers a pool fanning out to 16 JDCs at once. Held proposals are bounded
/// apart by [`MAX_PENDING_PROPOSALS`].
#[doc(hidden)]
pub const MAX_ADMITTED_PROPOSALS: usize = 16;

/// RAM trade (CONTRIBUTING 9): the bytes the admitted work holds per
/// session: 32 per wtxid, the coinbase prefix and suffix, and the raw
/// transactions a provide supplied. One worst-case proposal is ~2.2 MiB and
/// one worst-case provide ~6 MiB, so the bound admits two of those. Typical
/// jobs are ~100 KiB, so the count binds first. At [`crate::MAX_SESSIONS`]
/// sessions: ≤ 128 MiB.
#[doc(hidden)]
pub const MAX_ADMITTED_BYTES: usize = 16 << 20;

/// RAM trade (CONTRIBUTING 9): a proposal the TP answered
/// `ProvideMissingTransactions` waits here for the `.Success`, holding its
/// wtxids (≤ 2 MiB) and coinbase split (≤ 128 KiB) but no transactions:
/// ≤ 8 × ~2.2 MiB per session. Past the bound the oldest is dropped, and a
/// provide for it is `unknown-request-id`, the same recovery a JDS runs
/// when the hold timed out.
#[doc(hidden)]
pub const MAX_PENDING_PROPOSALS: usize = 8;

/// Fee-delta push settings (docs/sv2-template-provider.md C1).
#[derive(Clone, Copy)]
pub struct FeePush {
    pub delta: u64,
    pub interval: Duration,
}

/// The templates one session was sent. Ids are strictly increasing.
#[derive(Default)]
#[doc(hidden)]
pub struct Templates {
    pub last_id: u64,
    pub current_prev: Option<[u8; 32]>,
    /// `SetNewPrevHash.header_timestamp` sent for `current_prev`, and when.
    pub prev_sent: Option<(u32, Instant)>,
    /// `SetNewPrevHash.n_bits` and `target` sent for `current_prev`.
    pub sent_bits: Option<(u32, [u8; 32])>,
    /// A template was built since the last tip event.
    pub built_since_tip: bool,
    /// Fee delta is measured against the last pushed template.
    pub last_value_remaining: Option<u64>,
    pub retained: VecDeque<Retained>,
    /// `(prev hash, deadline)` for the tips this session moved off, oldest
    /// first, at most [`MAX_RETIRED_TIPS`]. Never holds `current_prev`.
    retired: VecDeque<([u8; 32], Instant)>,
}

#[doc(hidden)]
pub struct Retained {
    pub id: u64,
    pub job: template::Job,
    pub prev_sent: (u32, Instant),
    /// Set once the job's own parent is no longer the tip.
    pub retire_at: Option<Instant>,
}

type PermitWait = Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;

/// A proposal waiting for its `ProvideMissingTransactions.Success`.
struct Pending {
    proposal: Arc<Proposal>,
    /// The positions the `ProvideMissingTransactions` named.
    missing: Vec<u16>,
    expires_at: Instant,
}

impl Pending {
    /// The one expiry rule: taking a hold and the cleanup timer both ask it,
    /// so a provide that is handled before the timer still finds it expired.
    fn live(&self, now: Instant) -> bool {
        self.expires_at > now
    }
}

/// A proposal and what its JDS supplied, waiting for a validation slot.
struct Work {
    proposal: Arc<Proposal>,
    supplied: Supplied,
    /// What it holds against [`Admitted`] until it is answered.
    cost: usize,
}

/// Accepted-and-unanswered proposal work of one session, against
/// [`MAX_ADMITTED_PROPOSALS`] and [`MAX_ADMITTED_BYTES`].
#[derive(Default)]
struct Admitted {
    count: usize,
    bytes: usize,
}

impl Admitted {
    fn fits(&self, cost: usize) -> bool {
        self.count < MAX_ADMITTED_PROPOSALS && cost <= MAX_ADMITTED_BYTES - self.bytes
    }

    fn take(&mut self, cost: usize) {
        self.count += 1;
        self.bytes += cost;
    }

    fn credit(&mut self, cost: usize) {
        self.count -= 1;
        self.bytes -= cost;
    }
}

impl Templates {
    /// A job validated while the session is on another tip carries that
    /// tip's recorded deadline, which may already have passed: it is never
    /// given a fresh grace. A job on `current_prev`, or on a tip the session
    /// has not moved off yet (a validation can read the store tip before this
    /// session handles its event), has none, and the next [`Self::start_grace`]
    /// classifies it.
    #[doc(hidden)]
    pub fn retain(&mut self, id: u64, job: template::Job, prev_sent: (u32, Instant)) {
        if self.retained.len() == MAX_RETAINED {
            self.retained.pop_front();
        }
        let retire_at = self
            .retired
            .iter()
            .find(|(prev, _)| *prev == job.prev_hash)
            .map(|&(_, deadline)| deadline);
        self.retained.push_back(Retained {
            id,
            job,
            prev_sent,
            retire_at,
        });
    }

    /// Whether a tip event needs a rebuild: a new prev hash, or any build
    /// since the last event.
    #[doc(hidden)]
    pub fn on_tip(&mut self, hash: [u8; 32]) -> bool {
        // ChainHub publishes the store tip (connect or rollback reconnect),
        // then strips the block's txs from the mempool, then sends the event:
        // a build in between can select txs the block confirmed.
        std::mem::take(&mut self.built_since_tip) || self.current_prev != Some(hash)
    }

    #[doc(hidden)]
    pub fn get(&self, id: u64) -> Option<&Retained> {
        self.retained.iter().find(|r| r.id == id)
    }

    /// The session moves to `new_prev`. Entries on any other prev hash retire
    /// at `deadline` unless they already have one; entries on `new_prev` are
    /// current, including ones from before an earlier move off it. The tip
    /// left behind records `deadline` for jobs that finish on it later.
    #[doc(hidden)]
    pub fn start_grace(&mut self, new_prev: [u8; 32], deadline: Instant) {
        self.retired.retain(|(prev, _)| *prev != new_prev);
        if let Some(left) = self.current_prev.filter(|prev| *prev != new_prev) {
            if self.retired.len() == MAX_RETIRED_TIPS {
                self.retired.pop_front();
            }
            self.retired.push_back((left, deadline));
        }
        self.current_prev = Some(new_prev);
        for r in &mut self.retained {
            if r.job.prev_hash == new_prev {
                r.retire_at = None;
            } else {
                r.retire_at.get_or_insert(deadline);
            }
        }
    }

    #[doc(hidden)]
    pub fn next_retire(&self) -> Option<Instant> {
        self.retained.iter().filter_map(|r| r.retire_at).min()
    }

    #[doc(hidden)]
    pub fn retire(&mut self, now: Instant) {
        self.retained
            .retain(|r| r.retire_at.is_none_or(|d| d > now));
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
pub async fn serve(
    stream: TcpStream,
    responder: Box<Responder>,
    chain: Arc<ChainHub>,
    stale_grace: Duration,
    setup_timeout: Duration,
    idle_timeout: Option<Duration>,
    write_timeout: Duration,
    provide_timeout: Duration,
    fee_push: FeePush,
    constraints_cooldown: Duration,
    stats: Arc<Sv2TpStats>,
    flight: Arc<template::TemplateFlight>,
    permits: Arc<Semaphore>,
) -> io::Result<()> {
    let deadline = Instant::now() + setup_timeout;
    let setup = async {
        let mut conn = NoiseConn::accept(stream, responder, write_timeout).await?;
        let frame = conn.recv().await?;
        Ok::<_, io::Error>(on_setup(&mut conn, frame).await?.map(|flags| (conn, flags)))
    };
    let Some((conn, flags)) = tokio::time::timeout_at(deadline, setup)
        .await
        .map_err(|_| missed_setup_deadline())??
    else {
        return Ok(());
    };
    let (mut reader, writer) = conn.into_split();
    let (frames_tx, mut frames) = mpsc::channel(1);
    // Dropping the set aborts the reader when the session ends.
    let mut pump = JoinSet::new();
    pump.spawn(async move {
        loop {
            let f = reader.recv().await;
            let end = f.is_err();
            if frames_tx.send(f).await.is_err() || end {
                return;
            }
        }
    });
    let mut s = Session {
        conn: writer,
        chain,
        stale_grace,
        provide_timeout,
        fee_push,
        constraints_cooldown,
        stats,
        flight,
        job_validation: flags & REQUIRES_JOB_VALIDATION != 0,
        constraints: None,
        templates: Templates::default(),
        built_at: None,
        rebuild_at: None,
        superseded: 0,
        holding: false,
        held_logged: false,
        hold_check_at: None,
        fee_check_at: None,
        seen_updates: 0,
        permits,
        permit_wait: None,
        validations: JoinSet::new(),
        queued: VecDeque::new(),
        pending: VecDeque::new(),
        ids: HashSet::new(),
        admitted: Admitted::default(),
    };
    s.run(&mut frames, deadline, idle_timeout).await
}

#[doc(hidden)]
pub fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

#[doc(hidden)]
pub fn missed_setup_deadline() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "sv2: setup deadline")
}

#[doc(hidden)]
pub struct Session {
    pub conn: NoiseWriter,
    pub chain: Arc<ChainHub>,
    pub stale_grace: Duration,
    pub provide_timeout: Duration,
    pub fee_push: FeePush,
    pub constraints_cooldown: Duration,
    pub stats: Arc<Sv2TpStats>,
    /// Shared with every session on this listener.
    flight: Arc<template::TemplateFlight>,
    /// `SetupConnection` negotiated `REQUIRES_JOB_VALIDATION`.
    job_validation: bool,
    /// Last `CoinbaseOutputConstraints`: `(max_additional_size, sigops)`.
    pub constraints: Option<(u32, u16)>,
    pub templates: Templates,
    /// When `publish` last sent a template.
    pub built_at: Option<Instant>,
    /// Constraints-triggered rebuild deferred until `constraints_cooldown`.
    pub rebuild_at: Option<Instant>,
    /// Budgets that replaced a queued rebuild's since the last build.
    superseded: u32,
    /// Last `publish` returned without a template because the node was in IBD
    /// or relay was off. Cleared when a template is sent.
    holding: bool,
    held_logged: bool,
    /// While `holding`, the next time to try again. Relay turns on after the
    /// catch-up tip, so that tip's event can run before the pool is ready.
    hold_check_at: Option<Instant>,
    /// Next fee check: one interval after the last push or check.
    pub fee_check_at: Option<Instant>,
    /// `MempoolHub::template_updates` read before the last build.
    pub seen_updates: u64,
    /// Listener-wide validation permits ([`crate::Sv2TpConfig::validation_permits`]).
    permits: Arc<Semaphore>,
    /// This session's one pending acquire, present while `queued` is not
    /// empty. It is kept across loop turns so the session holds its place in
    /// the semaphore's queue.
    permit_wait: Option<PermitWait>,
    /// Validations this session started, for their verdicts. Each closure
    /// owns its permit and returns it only when the blocking work returns, so
    /// dropping the set with the session discards the verdicts but neither
    /// stops started work nor frees its permit early.
    validations: JoinSet<(Arc<Proposal>, Verdict, usize)>,
    /// Prechecked proposals waiting for a permit, oldest first.
    queued: VecDeque<Work>,
    /// Proposals waiting for their missing transactions, oldest first, at
    /// most `MAX_PENDING_PROPOSALS`.
    pending: VecDeque<Pending>,
    /// Request ids in use: queued, in flight, or held in `pending`.
    ids: HashSet<u32>,
    admitted: Admitted,
}

impl Session {
    /// `setup_deadline` covers the handshake through the first
    /// `CoinbaseOutputConstraints`, or through `SetupConnection.Success` for
    /// a session that negotiated `REQUIRES_JOB_VALIDATION`: it validates
    /// jobs and may never send constraints. After that, `idle_timeout`
    /// (`None`: no deadline) is refreshed only when a frame is handled, so
    /// tip and fee-check wakes do not keep a silent client.
    pub async fn run(
        &mut self,
        frames: &mut mpsc::Receiver<io::Result<Frame>>,
        setup_deadline: Instant,
        idle_timeout: Option<Duration>,
    ) -> io::Result<()> {
        let mut tips = self.chain.subscribe_tips();
        let mut idle_at = idle_timeout.map(|t| Instant::now() + t);
        loop {
            let retire_at = self
                .templates
                .next_retire()
                .into_iter()
                .chain(self.pending.front().map(|p| p.expires_at))
                .min();
            tokio::select! {
                f = frames.recv() => {
                    let Some(f) = f else { return Ok(()) };
                    if !self.on_frame(f?).await? {
                        return Ok(());
                    }
                    idle_at = idle_timeout.map(|t| Instant::now() + t);
                }
                tip = tips.recv() => match tip {
                    Ok(ev) if !self.templates.on_tip(ev.hash.to_byte_array()) => {}
                    Ok(_) | Err(RecvError::Lagged(_)) => self.publish().await?,
                    Err(RecvError::Closed) => return Ok(()),
                },
                Some(done) = self.validations.join_next(), if !self.validations.is_empty() => {
                    let (proposal, verdict, cost) = done.map_err(io::Error::other)?;
                    let request_id = proposal.request_id;
                    self.admitted.credit(cost);
                    if let Verdict::Missing(positions) = &verdict {
                        self.hold(proposal, positions.clone());
                    } else {
                        self.ids.remove(&request_id);
                    }
                    self.reply_propose(request_id, verdict).await?;
                }
                permit = next_permit(&mut self.permit_wait), if self.permit_wait.is_some() => {
                    self.start_validation(permit?);
                    self.want_permit();
                }
                _ = tokio::time::sleep_until(retire_at.unwrap_or_else(Instant::now)),
                    if retire_at.is_some() =>
                {
                    let now = Instant::now();
                    self.templates.retire(now);
                    let ids = &mut self.ids;
                    self.pending.retain(|p| {
                        let live = p.live(now);
                        if !live {
                            ids.remove(&p.proposal.request_id);
                        }
                        live
                    });
                }
                _ = tokio::time::sleep_until(self.rebuild_at.unwrap_or_else(Instant::now)),
                    if self.rebuild_at.is_some() =>
                {
                    self.publish().await?;
                }
                // CPU trade: `template_updates` is a counter, not a notifier,
                // so each session polls it once per interval. Sessions that
                // share a prev hash, coinbase budget, and this counter share
                // one build. The waiter parks on the session task.
                _ = tokio::time::sleep_until(self.fee_check_at.unwrap_or_else(Instant::now)),
                    if self.fee_check_at.is_some() =>
                {
                    self.check_fees().await?;
                }
                // Same interval, only while no template has been sent. The
                // counter the fee check watches is not armed until then, and
                // relay can turn on without another tip.
                _ = tokio::time::sleep_until(self.hold_check_at.unwrap_or_else(Instant::now)),
                    if self.hold_check_at.is_some() =>
                {
                    self.publish().await?;
                }
                _ = tokio::time::sleep_until(setup_deadline), if !self.set_up() => {
                    return Err(missed_setup_deadline());
                }
                _ = tokio::time::sleep_until(idle_at.unwrap_or_else(Instant::now)),
                    if idle_at.is_some() && self.set_up() =>
                {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "sv2: idle deadline"));
                }
            }
        }
    }

    /// Past the setup deadline's reach: constraints arrived, or the session
    /// negotiated job validation and needs none.
    fn set_up(&self) -> bool {
        self.job_validation || self.constraints.is_some()
    }

    /// `false`: close the session.
    pub async fn on_frame(&mut self, mut frame: Frame) -> io::Result<bool> {
        match frame.msg_type {
            MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS => {
                let Ok(c) = binary_sv2::from_bytes::<CoinbaseOutputConstraints>(&mut frame.payload)
                else {
                    rbitcoin_log::info!("sv2: undecodable CoinbaseOutputConstraints");
                    return Ok(false);
                };
                let c = Some((
                    c.coinbase_output_max_additional_size,
                    c.coinbase_output_max_additional_sigops,
                ));
                // Same budget: the last publish already applied it. A new
                // budget while holding is applied on the next hold check.
                // Publishing here would queue a rebuild that the check drops.
                let same = c == self.constraints;
                self.constraints = c;
                if same || self.holding {
                    return Ok(true);
                }
                match self.built_at.and_then(|t| {
                    constraints_rebuild_at(t, Instant::now(), self.constraints_cooldown)
                }) {
                    Some(at) => {
                        if self.rebuild_at.replace(at).is_some() {
                            self.superseded += 1;
                            if self.superseded > MAX_SUPERSEDED_CONSTRAINTS {
                                rbitcoin_log::info!(
                                    "sv2: CoinbaseOutputConstraints flood, closing"
                                );
                                return Ok(false);
                            }
                        }
                    }
                    _ => self.publish().await?,
                }
            }
            MESSAGE_TYPE_REQUEST_TRANSACTION_DATA => {
                on_request_transaction_data(&mut self.conn, frame, &self.templates).await?;
            }
            MESSAGE_TYPE_SUBMIT_SOLUTION => self.on_submit_solution(frame).await?,
            MESSAGE_TYPE_PROPOSE_TEMPLATE if self.job_validation => {
                let Some(p) = Proposal::decode(&mut frame.payload) else {
                    rbitcoin_log::info!("sv2: undecodable ProposeTemplate");
                    return Ok(true);
                };
                let cost = p.cost();
                let code = if self.ids.contains(&p.request_id) {
                    Err("duplicate-request-id")
                } else if !self.admitted.fits(cost) {
                    Err(UNAVAILABLE)
                } else {
                    p.precheck()
                };
                if let Err(code) = code {
                    self.reply_propose(p.request_id, Verdict::Rejected(code.into()))
                        .await?;
                    return Ok(true);
                }
                self.ids.insert(p.request_id);
                self.admitted.take(cost);
                self.queued.push_back(Work {
                    proposal: Arc::new(p),
                    supplied: Supplied::new(),
                    cost,
                });
                self.want_permit();
            }
            MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS if self.job_validation => {
                let Ok(m) =
                    binary_sv2::from_bytes::<ProvideMissingTransactionsSuccess>(&mut frame.payload)
                else {
                    rbitcoin_log::info!("sv2: undecodable ProvideMissingTransactions.Success");
                    return Ok(true);
                };
                let Some(Pending {
                    proposal, missing, ..
                }) = self.take_pending(m.request_id)
                else {
                    self.reply_propose(
                        m.request_id,
                        Verdict::Rejected("unknown-request-id".into()),
                    )
                    .await?;
                    return Ok(true);
                };
                let cost = proposal.cost()
                    + m.transaction_list
                        .iter()
                        .map(|t| t.as_ref().len())
                        .sum::<usize>();
                let accepted = if self.admitted.fits(cost) {
                    proposal.accept_supplied(&missing, &m.transaction_list)
                } else {
                    Err(UNAVAILABLE)
                };
                match accepted {
                    Ok(supplied) => {
                        self.admitted.take(cost);
                        self.queued.push_back(Work {
                            proposal,
                            supplied,
                            cost,
                        });
                        self.want_permit();
                    }
                    Err(code) => {
                        self.ids.remove(&m.request_id);
                        self.reply_propose(m.request_id, Verdict::Rejected(code.into()))
                            .await?;
                    }
                }
            }
            t => rbitcoin_log::info!("sv2: ignoring message {t:#x}"),
        }
        Ok(true)
    }

    /// Build on the current tip and send it.
    pub async fn publish(&mut self) -> io::Result<()> {
        self.rebuild_at = None;
        self.superseded = 0;
        match self.build().await? {
            Some(t) => {
                self.hold_check_at = None;
                self.send(t).await
            }
            None => {
                if self.holding {
                    self.hold_check_at = Some(Instant::now() + self.fee_push.interval);
                }
                Ok(())
            }
        }
    }

    /// With the tip unchanged, send a rebuild whose fees reach the last sent
    /// template's plus the delta. A rebuild on a new prev hash is dropped:
    /// its tip event publishes. A queued constraints rebuild publishes the
    /// latest mempool anyway, so the check leaves it alone.
    pub async fn check_fees(&mut self) -> io::Result<()> {
        self.fee_check_at = Some(Instant::now() + self.fee_push.interval);
        self.stats.fee_checks.note(0);
        let updates = self.chain.mempool().map_or(0, |m| m.template_updates());
        if updates == self.seen_updates || self.rebuild_at.is_some() {
            return Ok(());
        }
        // A check races ChainHub with no tip event in flight: a reorg pops the
        // tip block by block and only signals once the new branch connects,
        // so a tip read mid-disconnect can fail. The event that follows
        // publishes; one skipped check does not end the session, and the next
        // one retries the same mempool generation. No session reaches that
        // window deterministically.
        let t = match self.build().await {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(()),
            Err(e) => {
                rbitcoin_log::info!("sv2: fee check skipped ({e})");
                return Ok(());
            }
        };
        let Some(last) = self.templates.last_value_remaining else {
            return Ok(());
        };
        // Same prev hash, same height: value_remaining differs by fees only.
        if self.templates.current_prev == Some(t.job.prev_hash)
            && t.value_remaining >= last.saturating_add(self.fee_push.delta)
        {
            self.send(t).await?;
        }
        Ok(())
    }

    /// Template for the session's constraints. `None` before constraints, while
    /// in IBD, or before the pool is maintained (`-blocksonly` never starts
    /// it). A holding session tries again on the template interval, so
    /// maintenance starting after the catch-up tip still publishes. Peer
    /// relay can stay off.
    async fn build(&mut self) -> io::Result<Option<template::Template>> {
        let Some((size, sigops)) = self.constraints else {
            return Ok(None);
        };
        // Read before the build: a tx admitted during it moves the counter
        // past this, so the next check rebuilds. Stored only once the build
        // returns: a failed one leaves the generation for the next check.
        let updates = self.chain.mempool().map_or(0, |m| m.template_updates());
        // `template_prev` shares its mutex with the connect hold. Stamp bits
        // and time on the same thread, before the flight, so the cached
        // template is the one this key names.
        let chain = Arc::clone(&self.chain);
        let prepared = rbitcoin_net::off_pool(move || template::prepare_next(&chain)).await?;
        let t = if let Some(next) = prepared {
            let key = template::TemplateKey {
                prev_hash: next.prev_hash,
                max_additional_size: size,
                max_additional_sigops: sigops,
                template_updates: updates,
                header_timestamp: next.time,
                n_bits: next.bits.to_consensus(),
            };
            let c = Arc::clone(&self.chain);
            let stats = Arc::clone(&self.stats);
            self.flight
                .get_or_build(key, move || {
                    let _g = BlockingRegion::enter();
                    let unmaintained = c.mempool().is_none_or(|m| !m.pool_maintained());
                    if c.in_ibd() || unmaintained {
                        return Ok(None);
                    }
                    let started = std::time::Instant::now();
                    let t = template::build_next(&c, size, sigops, next)?;
                    if t.is_some() {
                        stats.builds.note(micros(started.elapsed()));
                    }
                    Ok(t)
                })
                .await?
        } else {
            None
        };
        self.seen_updates = updates;
        if t.is_none() {
            self.holding = true;
            if !self.held_logged {
                rbitcoin_log::info!("sv2: holding templates until the mempool is maintained");
                self.held_logged = true;
            }
        }
        Ok(t)
    }

    pub async fn send(&mut self, mut t: template::Template) -> io::Result<()> {
        self.holding = false;
        self.templates.last_id += 1;
        let template_id = self.templates.last_id;
        // sv2-spec 07 §7.3: a template on a new prev hash is future, then activated.
        let new_prev = self.templates.current_prev != Some(t.job.prev_hash);
        // §7.4: nBits comes once per prev hash. On min-difficulty networks the
        // build's bits follow the clock; a solution on this template is hashed
        // with the bits the client was sent.
        if let Some((n_bits, target)) = self.templates.sent_bits.filter(|_| !new_prev) {
            t.n_bits = n_bits;
            t.target = target;
            t.job.bits = Bits::Sent(n_bits);
        }
        let msg = t
            .to_message(template_id, new_prev)
            .map_err(|e| io::Error::other(format!("sv2 NewTemplate: {e:?}")))?;
        self.conn.send(MESSAGE_TYPE_NEW_TEMPLATE, msg).await?;
        self.templates.last_value_remaining = Some(t.value_remaining);
        let sent = Instant::now();
        self.built_at = Some(sent);
        self.fee_check_at = Some(sent + self.fee_push.interval);
        self.templates.built_since_tip = true;
        if new_prev {
            self.conn
                .send(MESSAGE_TYPE_SET_NEW_PREV_HASH, t.to_prev_hash(template_id))
                .await?;
            let now = Instant::now();
            self.templates.prev_sent = Some((t.job.header_timestamp, now));
            self.templates.sent_bits = Some((t.n_bits, t.target));
            self.templates
                .start_grace(t.job.prev_hash, now + self.stale_grace);
        }
        let prev_sent = self
            .templates
            .prev_sent
            .ok_or_else(|| io::Error::other("sv2: template before SetNewPrevHash"))?;
        self.templates.retain(template_id, t.job, prev_sent);
        Ok(())
    }

    /// A bad solution is logged and dropped. A decodable one on a retained
    /// template that meets its target goes to `ChainHub::accept_block`.
    /// The header's `nBits` are inside the hash ([`Bits`]): a pushed
    /// template uses the ones pinned for its prev hash and drops a timestamp
    /// that needs others; a custom job uses the ones consensus requires of
    /// its parent's child at that timestamp.
    pub async fn on_submit_solution(&mut self, mut frame: Frame) -> io::Result<()> {
        let Ok(m) = binary_sv2::from_bytes::<SubmitSolution>(&mut frame.payload) else {
            rbitcoin_log::info!("sv2: undecodable SubmitSolution");
            return Ok(());
        };
        let Some(r) = self.templates.get(m.template_id) else {
            rbitcoin_log::info!("sv2: SubmitSolution for unknown template {}", m.template_id);
            return Ok(());
        };
        let Ok(mut coinbase) =
            bitcoin::consensus::deserialize::<Transaction>(m.coinbase_tx.as_ref())
        else {
            rbitcoin_log::info!("sv2: undecodable SubmitSolution coinbase");
            return Ok(());
        };
        // BIP141: a committed block's coinbase witness is exactly the reserved
        // value. A client may omit it; the commitment used ours, so fill it.
        // Without a commitment output a coinbase witness is invalid, so a bare
        // coinbase stays bare. The txid (and the merkle root) does not cover
        // the witness.
        let committed = rbitcoin_consensus::witness_commitment_vout_index(&coinbase).is_some();
        if let Some(input) = coinbase.input.first_mut() {
            if committed && input.witness.is_empty() {
                input.witness = Witness::from_slice(&[template::WITNESS_RESERVED_VALUE]);
            }
        }
        // CPU trade: the coinbase is leaf 0 (always the left child), so its
        // txid folded over the template's path is the root the full txid
        // list would give. A miss on the target costs one fold, not a clone
        // and hash of every template tx plus ChainHub's connect path.
        let root = rbitcoin_store::merkle_root_from_branch(
            coinbase.compute_txid().to_byte_array(),
            &r.job.merkle_path,
            0,
        );
        let prev = BlockHash::from_byte_array(r.job.prev_hash);
        let stamp = m.header_timestamp;
        let bits = match r.job.bits {
            Bits::Sent(n_bits) => CompactTarget::from_consensus(n_bits),
            Bits::Consensus => {
                let bits_chain = Arc::clone(&self.chain);
                let expected = tokio::task::spawn_blocking(move || {
                    let _g = BlockingRegion::enter();
                    bits_chain.expected_child_bits(&prev, stamp)
                })
                .await
                .map_err(io::Error::other)?;
                let Some(bits) = expected else {
                    rbitcoin_log::info!(
                        "sv2: SubmitSolution template {}: parent {prev} unknown; dropping",
                        m.template_id
                    );
                    return Ok(());
                };
                bits
            }
        };
        let header = block::Header {
            version: block::Version::from_consensus(m.version as i32),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(root),
            time: stamp,
            bits,
            nonce: m.header_nonce,
        };
        if header.validate_pow(header.target()).is_err() {
            rbitcoin_log::info!(
                "sv2: SubmitSolution {} misses the template target",
                header.block_hash()
            );
            return Ok(());
        }
        // A pushed template pinned its nBits when this prev hash was sent. A
        // timestamp past the min-difficulty gap needs the pow-limit bits
        // instead, and rewriting them would change the hash the miner found.
        if let Bits::Sent(_) = r.job.bits {
            let bits_chain = Arc::clone(&self.chain);
            let pinned = header.bits;
            let other_bits = tokio::task::spawn_blocking(move || {
                let _g = BlockingRegion::enter();
                submit_timestamp_needs_other_bits(&bits_chain, prev, stamp, pinned)
            })
            .await
            .map_err(io::Error::other)?;
            if other_bits {
                rbitcoin_log::info!(
                    "sv2: SubmitSolution {} timestamp needs different bits; dropping",
                    header.block_hash()
                );
                return Ok(());
            }
        }
        // Diagnostic only: a miner clock ahead of ours rolls past the wall
        // time since SetNewPrevHash. accept_block enforces the consensus
        // bounds (> MTP, < now + 2h), so the block is still submitted.
        let (sent_ts, sent_at) = r.prev_sent;
        let rolled =
            u64::try_from(sent_at.elapsed().as_millis().div_ceil(1000)).unwrap_or(u64::MAX);
        if u64::from(m.header_timestamp) < u64::from(sent_ts)
            || u64::from(m.header_timestamp) > u64::from(sent_ts).saturating_add(rolled)
        {
            rbitcoin_log::info!(
                "sv2: SubmitSolution template {} header_timestamp {} outside [{sent_ts}, +{rolled}s]; submitting",
                m.template_id,
                m.header_timestamp
            );
        }
        let mut txdata = Vec::with_capacity(1 + r.job.txs.len());
        txdata.push(coinbase);
        txdata.extend(r.job.txs.iter().map(|tx| Transaction::clone(tx)));
        let block = Block { header, txdata };
        let hash = block.block_hash();
        let outcome = self.chain.accept_block_async(block).await;
        match outcome {
            Ok(o) => rbitcoin_log::info!("sv2: SubmitSolution {hash}: {o:?}"),
            Err(e) => rbitcoin_log::info!("sv2: SubmitSolution {hash} rejected: {e}"),
        }
        Ok(())
    }

    /// Ask for a permit for the oldest queued proposal. The session has at
    /// most one acquire pending, so it waits its turn in the semaphore's
    /// queue as one client, however much it has queued. Other frames and the
    /// loop's timers run meanwhile; the reply comes from the `join_next` arm,
    /// paired by `request_id`.
    fn want_permit(&mut self) {
        if self.permit_wait.is_none() && !self.queued.is_empty() {
            self.permit_wait = Some(Box::pin(Arc::clone(&self.permits).acquire_owned()));
        }
    }

    fn start_validation(&mut self, permit: OwnedSemaphorePermit) {
        let Some(Work {
            proposal,
            supplied,
            cost,
        }) = self.queued.pop_front()
        else {
            return;
        };
        let c = Arc::clone(&self.chain);
        let stats = Arc::clone(&self.stats);
        self.validations.spawn_blocking(move || {
            let _permit = permit;
            let _running = stats.enter_validation();
            let _g = BlockingRegion::enter();
            let verdict = job::validate(&c, &proposal, &supplied);
            (proposal, verdict, cost)
        });
    }

    /// The live hold for `request_id`, removed. One past its deadline is
    /// absent whether or not the cleanup timer has run yet, and its id is
    /// free again: the timer only returns that memory earlier.
    fn take_pending(&mut self, request_id: u32) -> Option<Pending> {
        let at = self
            .pending
            .iter()
            .position(|p| p.proposal.request_id == request_id)?;
        let held = self.pending.remove(at)?;
        if held.live(Instant::now()) {
            Some(held)
        } else {
            self.ids.remove(&request_id);
            None
        }
    }

    /// docs/sv2-job-validation.md §4.2: keep the proposal for its
    /// `ProvideMissingTransactions.Success`, `provide_timeout` at most.
    fn hold(&mut self, proposal: Arc<Proposal>, missing: Vec<u16>) {
        if self.pending.len() == MAX_PENDING_PROPOSALS {
            if let Some(dropped) = self.pending.pop_front() {
                self.ids.remove(&dropped.proposal.request_id);
            }
        }
        self.pending.push_back(Pending {
            proposal,
            missing,
            expires_at: Instant::now() + self.provide_timeout,
        });
    }

    /// docs/sv2-job-validation.md §4: a valid job is retained under the next
    /// template id and answered `Success`; a rejected one answers `Error`; one
    /// the mempool cannot complete is asked for its missing transactions.
    async fn reply_propose(&mut self, request_id: u32, verdict: Verdict) -> io::Result<()> {
        let wire = |e: binary_sv2::Error| io::Error::other(format!("sv2 ProposeTemplate: {e:?}"));
        match verdict {
            Verdict::Missing(positions) => {
                let reply = ProvideMissingTransactions {
                    request_id,
                    unknown_tx_position_list: Seq064K::new(positions).map_err(wire)?,
                };
                self.conn
                    .send(MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS, reply)
                    .await
            }
            Verdict::Valid { fees, job } => {
                self.templates.last_id += 1;
                let template_id = self.templates.last_id;
                let prev_sent = self
                    .templates
                    .prev_sent
                    .unwrap_or((job.header_timestamp, Instant::now()));
                let prev_hash = job.prev_hash;
                self.templates.retain(template_id, job, prev_sent);
                let reply = ProposeTemplateSuccess {
                    request_id,
                    template_id,
                    prev_hash: U256::from(&prev_hash),
                    fees,
                };
                self.conn
                    .send(MESSAGE_TYPE_PROPOSE_TEMPLATE_SUCCESS, reply)
                    .await
            }
            Verdict::Rejected(code) => {
                let reply = ProposeTemplateError {
                    request_id,
                    error_code: Str0255::try_from(code.as_str()).map_err(wire)?,
                    error_details: B064K::try_from(&[][..]).map_err(wire)?,
                };
                self.conn
                    .send(MESSAGE_TYPE_PROPOSE_TEMPLATE_ERROR, reply)
                    .await
            }
        }
    }
}

/// The permit the session's pending acquire resolves to; pending forever
/// while it has none.
async fn next_permit(wait: &mut Option<PermitWait>) -> io::Result<OwnedSemaphorePermit> {
    let Some(pending) = wait.as_mut() else {
        return std::future::pending().await;
    };
    let granted = pending.await;
    *wait = None;
    granted.map_err(io::Error::other)
}

/// `true` when `header_time` at `prev`'s child expects compact bits other
/// than the ones pinned on the template.
fn submit_timestamp_needs_other_bits(
    chain: &ChainHub,
    prev: BlockHash,
    header_time: u32,
    pinned: CompactTarget,
) -> bool {
    let Ok(Some(parent)) = chain.query.height_of_hash(&prev.to_byte_array()) else {
        return false;
    };
    let Some(next) = parent.0.checked_add(1) else {
        return false;
    };
    let Ok(bits) = rbitcoin_query::expected_next_bits(
        chain.query.as_ref(),
        &chain.params,
        rbitcoin_primitives::Height(next),
        header_time,
    ) else {
        return false;
    };
    bits != pinned
}

#[doc(hidden)]
pub fn setup_error(m: &SetupConnection) -> Option<(u32, &'static str)> {
    if m.protocol != Protocol::TemplateDistributionProtocol {
        return Some((0, ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL));
    }
    if !(m.min_version..=m.max_version).contains(&TDP_VERSION) {
        return Some((0, ERROR_CODE_SETUP_CONNECTION_PROTOCOL_VERSION_MISMATCH));
    }
    // docs/sv2-job-validation.md §3 defines bit 0; every other set bit is
    // unsupported.
    if m.flags & !REQUIRES_JOB_VALIDATION != 0 {
        return Some((
            m.flags,
            ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS,
        ));
    }
    None
}

/// The negotiated flags; `None`: close the session.
pub async fn on_setup(conn: &mut NoiseConn, mut frame: Frame) -> io::Result<Option<u32>> {
    if frame.msg_type != MESSAGE_TYPE_SETUP_CONNECTION {
        rbitcoin_log::info!("sv2: message {:#x} before SetupConnection", frame.msg_type);
        return Ok(None);
    }
    let Ok(setup) = binary_sv2::from_bytes::<SetupConnection>(&mut frame.payload) else {
        rbitcoin_log::info!("sv2: undecodable SetupConnection");
        return Ok(None);
    };
    if let Some((flags, code)) = setup_error(&setup) {
        let error_code = Str0255::try_from(code)
            .map_err(|e| io::Error::other(format!("sv2 error code: {e:?}")))?;
        let reply = SetupConnectionError { flags, error_code };
        conn.send(MESSAGE_TYPE_SETUP_CONNECTION_ERROR, reply)
            .await?;
        return Ok(None);
    }
    let reply = SetupConnectionSuccess {
        used_version: TDP_VERSION,
        flags: setup.flags,
    };
    conn.send(MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, reply)
        .await?;
    Ok(Some(setup.flags))
}

/// An id this session was sent but no longer retains is stale; any other
/// unknown id was never sent.
pub async fn on_request_transaction_data(
    conn: &mut NoiseWriter,
    mut frame: Frame,
    templates: &Templates,
) -> io::Result<()> {
    let Ok(RequestTransactionData { template_id }) = binary_sv2::from_bytes(&mut frame.payload)
    else {
        rbitcoin_log::info!("sv2: undecodable RequestTransactionData");
        return Ok(());
    };
    let Some(Retained { job, .. }) = templates.get(template_id) else {
        let code = if template_id <= templates.last_id {
            ERROR_CODE_REQUEST_TRANSACTION_DATA_STALE_TEMPLATE_ID
        } else {
            ERROR_CODE_REQUEST_TRANSACTION_DATA_TEMPLATE_ID_NOT_FOUND
        };
        let reply = RequestTransactionDataError {
            template_id,
            error_code: Str0255::try_from(code)
                .map_err(|e| io::Error::other(format!("sv2 error code: {e:?}")))?,
        };
        return conn
            .send(MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR, reply)
            .await;
    };
    let raw: Vec<Vec<u8>> = job
        .txs
        .iter()
        .map(|tx| bitcoin::consensus::encode::serialize(tx.as_ref()))
        .collect();
    let wire = |e: binary_sv2::Error| {
        io::Error::other(format!("sv2 RequestTransactionData.Success: {e:?}"))
    };
    let reply = RequestTransactionDataSuccess {
        template_id,
        excess_data: B064K::try_from(&[][..]).map_err(wire)?,
        transaction_list: Seq064K::new(
            raw.iter()
                .map(|tx| B016M::try_from(&tx[..]))
                .collect::<Result<_, _>>()
                .map_err(wire)?,
        )
        .map_err(wire)?,
    };
    conn.send(MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS, reply)
        .await
}
