//! k-of-n decision over the auditors' answers (iroha3 PLAN S11/S12, ANALYST: 2-of-3 with BI and orgs A and B).
//!
//! The driver asks each auditor to `/approve` a leg. The chain accepts the leg once the policy's `min_approvals` approvals are
//! in, so the driver stops asking as soon as that is certain either way: k approvals = go; fewer than k can still come = abort.
//! An auditor that is offline, or rejects, simply does not count as an approval.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Approved,
    Rejected,
    Unavailable,
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Approved,
    Rejected,
    Wait,
}

pub fn decide(k: usize, answers: &[Answer]) -> Verdict {
    if k == 0 {
        return Verdict::Rejected;
    }
    let approved = answers.iter().filter(|a| **a == Answer::Approved).count();
    let pending = answers.iter().filter(|a| **a == Answer::Pending).count();
    if approved >= k {
        Verdict::Approved
    } else if approved + pending < k {
        Verdict::Rejected
    } else {
        Verdict::Wait
    }
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
