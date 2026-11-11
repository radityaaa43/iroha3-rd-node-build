#[cfg(test)]
mod tests {
    use super::Answer::{Approved as A, Pending as P, Rejected as R, Unavailable as U};
    use super::*;

    #[test]
    fn k_approvals_decide_as_soon_as_they_are_in() {
        assert_eq!(decide(2, &[A, A, P]), Verdict::Approved);
        assert_eq!(decide(2, &[A, P, A]), Verdict::Approved);
        assert_eq!(decide(1, &[A]), Verdict::Approved);
        assert_eq!(decide(3, &[A, A, A]), Verdict::Approved);
    }

    #[test]
    fn an_auditor_that_is_offline_does_not_stop_k_of_n() {
        // BI offline, orgs A and B approve: 2-of-3 commits (the ANALYST RED proof, unit level).
        assert_eq!(decide(2, &[U, A, A]), Verdict::Approved);
        // A rejecting auditor does not stop it either while k others approve.
        assert_eq!(decide(2, &[R, A, A]), Verdict::Approved);
    }

    #[test]
    fn fewer_than_k_approvals_never_approve() {
        // Only one approval of 2-of-3 is NOT enough, whatever the others do.
        assert_eq!(decide(2, &[A, U, U]), Verdict::Rejected);
        assert_eq!(decide(2, &[A, R, U]), Verdict::Rejected);
        assert_eq!(decide(2, &[R, R, A]), Verdict::Rejected);
        assert_eq!(decide(1, &[R]), Verdict::Rejected);
        assert_eq!(decide(1, &[U]), Verdict::Rejected);
    }

    #[test]
    fn it_waits_only_while_k_is_still_reachable() {
        assert_eq!(decide(2, &[A, P, P]), Verdict::Wait);
        assert_eq!(decide(2, &[P, P, P]), Verdict::Wait);
        assert_eq!(decide(2, &[R, P, P]), Verdict::Wait);
        // k can no longer be reached: stop waiting
        assert_eq!(decide(2, &[R, R, P]), Verdict::Rejected);
        assert_eq!(decide(3, &[A, A, R]), Verdict::Rejected);
    }

    #[test]
    fn k_of_zero_never_approves() {
        assert_eq!(decide(0, &[A, A]), Verdict::Rejected);
        assert_eq!(decide(2, &[]), Verdict::Rejected);
    }
}
