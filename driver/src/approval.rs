//! k-of-n decision over the auditors' answers (iroha3 PLAN S11/S12; ANALYST Q-D = (b2), client policy, DELTA 10a).
//!
//! (b2) is client policy; the chain rule is k-of-n approvals (iroha@071e281e private_settlement.rs:3958): the chain commits a leg
//! once `min_approvals` approvals are in and knows nothing about rejects. The driver therefore asks ALL auditors in PARALLEL and
//! decides only after every answer is in or the deadline passed: any explicit Reject aborts (BI's included, never outvoted); else
//! k approvals proceed; an auditor that is offline or too slow counts as no approval and never blocks (R2), so BI offline with A
//! and B approving proceeds. A colluding pair of transacting auditors can override; detected by the reconcile control (condition 2).
//! Late answers are logged, not counted.

use std::{
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Approved,
    Rejected,
    Unavailable,
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// k approvals, nothing rejected, nothing pending.
    Approved,
    /// At least one auditor rejected explicitly.
    Rejected,
    /// No Reject, but fewer than k approvals can be reached.
    Insufficient,
    /// Not decidable yet: an answer is still pending.
    Wait,
}

pub fn decide(k: usize, answers: &[Answer]) -> Verdict {
    if k == 0 {
        return Verdict::Insufficient;
    }
    if answers.contains(&Answer::Rejected) {
        return Verdict::Rejected;
    }
    let approved = answers.iter().filter(|a| **a == Answer::Approved).count();
    let pending = answers.iter().filter(|a| **a == Answer::Pending).count();
    if approved + pending < k {
        Verdict::Insufficient
    } else if pending > 0 {
        Verdict::Wait
    } else {
        Verdict::Approved
    }
}

/// The abort reason the driver reports.
pub fn reason(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Rejected => "rejected",
        Verdict::Insufficient => "insufficient approvals",
        Verdict::Approved | Verdict::Wait => "",
    }
}

/// Ask `n` auditors in parallel (`ask(i)` blocks for auditor `i`) and decide. Returns as soon as the verdict is certain (a
/// Reject, or k unreachable) or all answered; at `deadline` every unanswered auditor counts as Unavailable. Late answers are
/// logged by their thread and ignored.
pub fn gather(k: usize, n: usize, deadline: Duration, ask: Arc<dyn Fn(usize) -> Answer + Send + Sync>) -> (Verdict, Vec<Answer>) {
    let (tx, rx) = mpsc::channel();
    for i in 0..n {
        let (tx, ask) = (tx.clone(), ask.clone());
        thread::spawn(move || {
            let answer = ask(i);
            if tx.send((i, answer)).is_err() {
                eprintln!("auditor {i} answered {answer:?} after the decision: ignored");
            }
        });
    }
    drop(tx);
    let mut answers = vec![Answer::Pending; n];
    let end = Instant::now() + deadline;
    loop {
        let verdict = decide(k, &answers);
        if verdict != Verdict::Wait {
            return (verdict, answers);
        }
        match rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
            Ok((i, answer)) => answers[i] = answer,
            Err(_) => break,
        }
    }
    for answer in &mut answers {
        if *answer == Answer::Pending {
            *answer = Answer::Unavailable;
        }
    }
    (decide(k, &answers), answers)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use super::Answer::{Approved as A, Pending as P, Rejected as R, Unavailable as U};
    use super::*;

    #[test]
    fn any_explicit_reject_aborts_even_when_k_others_approve() {
        // Governance (b2): an auditor's Reject (BI's included) is never outvoted.
        assert_eq!(decide(2, &[R, A, A]), Verdict::Rejected);
        assert_eq!(decide(2, &[A, R, A]), Verdict::Rejected);
        assert_eq!(decide(2, &[R, P, P]), Verdict::Rejected);
        assert_eq!(decide(1, &[R]), Verdict::Rejected);
    }

    #[test]
    fn an_auditor_that_is_offline_never_blocks_k_of_n() {
        // BI offline, orgs A and B approve: 2-of-3 proceeds (R2).
        assert_eq!(decide(2, &[U, A, A]), Verdict::Approved);
        assert_eq!(decide(2, &[A, U, A]), Verdict::Approved);
        assert_eq!(decide(3, &[A, A, A]), Verdict::Approved);
        assert_eq!(decide(1, &[A]), Verdict::Approved);
    }

    #[test]
    fn it_waits_for_every_answer_before_it_approves() {
        // b1 (stop at k approvals) is rejected: a pending auditor may still reject.
        assert_eq!(decide(2, &[A, A, P]), Verdict::Wait);
        assert_eq!(decide(2, &[P, A, U]), Verdict::Wait);
        assert_eq!(decide(2, &[P, P, P]), Verdict::Wait);
    }

    #[test]
    fn too_few_approvals_with_nothing_pending_is_insufficient() {
        assert_eq!(decide(2, &[A, U, U]), Verdict::Insufficient);
        assert_eq!(decide(2, &[U, U, U]), Verdict::Insufficient);
        assert_eq!(decide(1, &[U]), Verdict::Insufficient);
        // k can no longer be reached even if every pending approves
        assert_eq!(decide(3, &[A, U, P]), Verdict::Insufficient);
    }

    #[test]
    fn k_of_zero_or_no_auditor_never_approves() {
        assert_eq!(decide(0, &[A, A]), Verdict::Insufficient);
        assert_eq!(decide(2, &[]), Verdict::Insufficient);
    }

    #[test]
    fn the_abort_reasons_are_rejected_and_insufficient_approvals() {
        assert_eq!(reason(Verdict::Rejected), "rejected");
        assert_eq!(reason(Verdict::Insufficient), "insufficient approvals");
    }

    fn ask(script: Vec<(Duration, Answer)>) -> Arc<dyn Fn(usize) -> Answer + Send + Sync> {
        Arc::new(move |i| {
            std::thread::sleep(script[i].0);
            script[i].1
        })
    }

    const FAST: Duration = Duration::from_millis(5);
    const SLOW: Duration = Duration::from_secs(3);

    #[test]
    fn gather_asks_all_auditors_in_parallel_and_decides_after_the_last_answer() {
        let started = Instant::now();
        let (verdict, answers) = gather(2, 3, Duration::from_secs(2), ask(vec![(Duration::from_millis(300), A); 3]));
        assert_eq!((verdict, answers), (Verdict::Approved, vec![A, A, A]));
        assert!(started.elapsed() < Duration::from_millis(800), "three 300 ms calls must overlap, not add up");
    }

    #[test]
    fn gather_stops_at_once_on_a_reject_without_waiting_for_a_slow_auditor() {
        let started = Instant::now();
        let (verdict, answers) = gather(2, 3, Duration::from_secs(10), ask(vec![(FAST, R), (FAST, A), (SLOW, A)]));
        assert_eq!(verdict, Verdict::Rejected);
        assert_eq!(answers[0], R);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn gather_counts_an_auditor_past_the_deadline_as_unavailable_and_still_proceeds_on_k() {
        let started = Instant::now();
        let (verdict, answers) = gather(2, 3, Duration::from_millis(300), ask(vec![(SLOW, A), (FAST, A), (FAST, A)]));
        assert_eq!((verdict, answers), (Verdict::Approved, vec![U, A, A]));
        assert!(started.elapsed() >= Duration::from_millis(300) && started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn gather_with_too_few_answers_by_the_deadline_is_insufficient() {
        let (verdict, answers) = gather(2, 3, Duration::from_millis(300), ask(vec![(SLOW, A), (SLOW, A), (FAST, A)]));
        assert_eq!((verdict, answers), (Verdict::Insufficient, vec![U, U, A]));
    }
}
