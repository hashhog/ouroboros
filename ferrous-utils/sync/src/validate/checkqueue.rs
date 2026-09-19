//! CCheckQueue-style parallel script verification.
//!
//! Reference: bitcoin-core `src/checkqueue.h`, `validation.cpp` ConnectBlock
//! (`CScriptCheck` batched per input), `init.cpp` `-par`,
//! `node/chainstatemanager_args.cpp:53-60`, `validation.h`
//! `MAX_SCRIPTCHECK_THREADS{15}`.
//!
//! Shape: every input's `verify_input` is a job on a bounded queue; workers
//! drain batches of at most [`SCRIPT_CHECK_BATCH_SIZE`] (128). The block is
//! accepted only if every check returns true. The reject reason is the
//! **lowest job index** that failed, so the decision cannot depend on how
//! the work was split (1 worker and N workers return the same error).
//!
//! The Python interpreter holds the GIL and cannot use this pool; only the
//! native interpreter (`verify_input`) runs here, off-GIL.

use super::interpreter::{verify_input, ScriptError, TxContext};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Core `MAX_SCRIPTCHECK_THREADS` (`validation.h:90`): hard cap on extra
/// script-check worker threads. Combined with the calling/master thread this
/// is at most 16 verification threads.
pub const MAX_SCRIPTCHECK_THREADS: usize = 15;

/// Core `DEFAULT_SCRIPTCHECK_THREADS` (`chainstatemanager_args.h:14`):
/// `0` means auto-detect (`GetNumCores()`).
pub const DEFAULT_SCRIPTCHECK_THREADS: i32 = 0;

/// Core `CCheckQueue` batch size (`validation.cpp:6136`, `nBatchSize=128`).
/// Each worker pulls at most this many checks at a time so per-worker
/// buffers stay O(batch), not O(inputs × workers).
pub const SCRIPT_CHECK_BATCH_SIZE: usize = 128;

/// `--par` value consumed by [`resolve_script_check_threads`]. Written by
/// [`init_script_check_threads`] before the first ConnectBlock; default 0
/// (auto) matches Core.
static REQUESTED_PAR: AtomicI32 = AtomicI32::new(DEFAULT_SCRIPTCHECK_THREADS);

/// One input's script check (Core `CScriptCheck`).
///
/// `index` is the caller's job ordinal — ConnectBlock assigns these in
/// block order so the lowest failing index is the first failing input.
pub struct ScriptCheck {
    pub ctx: Arc<TxContext>,
    pub n_in: usize,
    pub script_sig: Vec<u8>,
    pub script_pubkey: Vec<u8>,
    pub flags: u32,
    pub amount: i64,
    pub index: usize,
}

fn num_cores() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(1)
        .max(1)
}

/// Resolve `--par=<n>` to the number of script-verification threads.
///
/// Mirrors Bitcoin Core `ApplyArgsManOptions` (`chainstatemanager_args.cpp:53-60`)
/// plus the `CCheckQueue` constructor clamp (`validation.cpp:6136`):
///
/// ```text
/// script_threads = par
/// if script_threads <= 0: script_threads += GetNumCores()  // 0=auto, -n=leave n free
/// worker_threads_num = clamp(script_threads - 1, 0, MAX_SCRIPTCHECK_THREADS)
/// ```
///
/// Core then runs `worker_threads_num` extra threads plus the calling
/// (master) thread. We size the pool at `worker_threads_num + 1` (always ≥ 1)
/// to keep the same total. `--par=1` is therefore serial (one thread).
pub fn resolve_script_check_threads(par: i32) -> usize {
    let cores = num_cores();
    let mut script_threads = par;
    if script_threads <= 0 {
        script_threads = script_threads.saturating_add(cores);
    }
    let workers = (script_threads - 1).clamp(0, MAX_SCRIPTCHECK_THREADS as i32);
    (workers + 1) as usize
}

/// Record `--par` for subsequent [`script_check_thread_count`] calls.
pub fn init_script_check_threads(par: i32) -> usize {
    REQUESTED_PAR.store(par, Ordering::SeqCst);
    resolve_script_check_threads(par)
}

/// Live resolved thread count from the last [`init_script_check_threads`]
/// (or Core's default 0 = auto if never initialized).
pub fn script_check_thread_count() -> usize {
    resolve_script_check_threads(REQUESTED_PAR.load(Ordering::SeqCst))
}

struct Fail {
    index: usize,
    err: ScriptError,
}

fn run_serial(checks: &[ScriptCheck]) -> Result<(), (usize, ScriptError)> {
    let mut fail: Option<Fail> = None;
    for c in checks {
        if let Err(e) = verify_input(
            &c.ctx,
            c.n_in,
            &c.script_sig,
            &c.script_pubkey,
            c.flags,
            c.amount,
        ) {
            match &fail {
                Some(f) if f.index <= c.index => {}
                _ => {
                    fail = Some(Fail {
                        index: c.index,
                        err: e,
                    })
                }
            }
        }
    }
    match fail {
        None => Ok(()),
        Some(f) => Err((f.index, f.err)),
    }
}

/// Claim a batch of at most [`SCRIPT_CHECK_BATCH_SIZE`] jobs.
///
/// Dynamic sizing (Core `checkqueue.h:117-121`): aim for ~`n_workers`
/// remaining batches so workers finish together, never larger than 128,
/// never empty. CAS so two workers cannot claim the same range. The work
/// vector itself is borrowed — workers do not clone the job list.
fn claim_batch(next: &AtomicUsize, len: usize, n_workers: usize) -> Option<std::ops::Range<usize>> {
    loop {
        let start = next.load(Ordering::Relaxed);
        if start >= len {
            return None;
        }
        let remaining = len - start;
        let batch = remaining
            .div_ceil(n_workers.max(1))
            .clamp(1, SCRIPT_CHECK_BATCH_SIZE);
        match next.compare_exchange_weak(start, start + batch, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return Some(start..start + batch),
            Err(_) => continue,
        }
    }
}

fn run_one(c: &ScriptCheck) -> Result<(), ScriptError> {
    verify_input(
        &c.ctx,
        c.n_in,
        &c.script_sig,
        &c.script_pubkey,
        c.flags,
        c.amount,
    )
}

/// Run `checks` with exactly `n_workers` threads (1 = serial).
///
/// On failure returns `(lowest_failing_index, error)` so 1 worker and N
/// workers report the same reason. Every check is executed: skipping a
/// lower-index job after a later job failed would make the reason depend
/// on the schedule.
pub fn run_script_checks_with_n(
    n_workers: usize,
    checks: &[ScriptCheck],
) -> Result<(), (usize, ScriptError)> {
    if checks.is_empty() {
        return Ok(());
    }
    let n = n_workers.max(1).min(checks.len());
    if n == 1 {
        return run_serial(checks);
    }

    let next = AtomicUsize::new(0);
    let fail: Mutex<Option<Fail>> = Mutex::new(None);

    std::thread::scope(|scope| {
        for _ in 0..n {
            scope.spawn(|| {
                let mut local: Option<Fail> = None;
                while let Some(range) = claim_batch(&next, checks.len(), n) {
                    for c in &checks[range] {
                        if let Err(e) = run_one(c) {
                            match &local {
                                Some(f) if f.index <= c.index => {}
                                _ => {
                                    local = Some(Fail {
                                        index: c.index,
                                        err: e,
                                    })
                                }
                            }
                        }
                    }
                }
                if let Some(f) = local {
                    let mut g = fail.lock().expect("script-check fail mutex");
                    match &*g {
                        Some(cur) if cur.index <= f.index => {}
                        _ => *g = Some(f),
                    }
                }
            });
        }
    });

    match fail.into_inner().expect("script-check fail mutex") {
        None => Ok(()),
        Some(f) => Err((f.index, f.err)),
    }
}

/// Run with the process `--par` resolution (production ConnectBlock).
pub fn run_script_checks(checks: &[ScriptCheck]) -> Result<(), (usize, ScriptError)> {
    run_script_checks_with_n(script_check_thread_count(), checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::interpreter::{Tx, TxIn, TxOut};

    fn dummy_ctx() -> Arc<TxContext> {
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prevout_hash: [0; 32],
                prevout_n: 0xffff_ffff,
                script_sig: vec![],
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 900,
                script_pubkey: vec![0x51],
            }],
            locktime: 0,
        };
        Arc::new(TxContext::new(tx, None).unwrap())
    }

    fn mk(ctx: &Arc<TxContext>, spk: Vec<u8>, index: usize) -> ScriptCheck {
        ScriptCheck {
            ctx: Arc::clone(ctx),
            n_in: 0,
            script_sig: vec![],
            script_pubkey: spk,
            flags: 0,
            amount: 1000,
            index,
        }
    }

    fn op_true() -> Vec<u8> {
        vec![0x51]
    }
    fn op_false() -> Vec<u8> {
        vec![0x00]
    }

    #[test]
    fn par_resolve_matches_core() {
        assert_eq!(DEFAULT_SCRIPTCHECK_THREADS, 0);
        assert_eq!(MAX_SCRIPTCHECK_THREADS, 15);
        assert_eq!(SCRIPT_CHECK_BATCH_SIZE, 128);
        assert_eq!(resolve_script_check_threads(1), 1);
        assert_eq!(resolve_script_check_threads(4), 4);
        assert_eq!(resolve_script_check_threads(16), 16);
        assert_eq!(
            resolve_script_check_threads(100),
            MAX_SCRIPTCHECK_THREADS + 1
        );
        let auto = resolve_script_check_threads(0);
        assert!((1..=MAX_SCRIPTCHECK_THREADS + 1).contains(&auto));
        let leave_one = resolve_script_check_threads(-1);
        assert!((1..=MAX_SCRIPTCHECK_THREADS + 1).contains(&leave_one));
        assert!(leave_one <= auto);
    }

    #[test]
    fn identity_accept_1_vs_n() {
        let ctx = dummy_ctx();
        let checks: Vec<_> = (0..64).map(|i| mk(&ctx, op_true(), i)).collect();
        let one = run_script_checks_with_n(1, &checks);
        let eight = run_script_checks_with_n(8, &checks);
        assert!(one.is_ok(), "{one:?}");
        assert_eq!(one, eight);
    }

    #[test]
    fn identity_fail_lowest_index() {
        let ctx = dummy_ctx();
        let mut checks: Vec<_> = (0..64).map(|i| mk(&ctx, op_true(), i)).collect();
        checks[37] = mk(&ctx, op_false(), 37);
        let serial = run_script_checks_with_n(1, &checks);
        assert_eq!(serial, Err((37, ScriptError::EvalFalse)));
        for n in [2, 4, 8] {
            assert_eq!(run_script_checks_with_n(n, &checks), serial, "n={n}");
        }
    }
}
