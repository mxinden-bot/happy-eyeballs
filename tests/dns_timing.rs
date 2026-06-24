//! The DNS lookup interval reported for the winning connection must be anchored
//! to the record that resolved its address, not to the connection's start.
//!
//! Records resolve at different times and many connections may be raced before
//! one wins. Reporting the winning connection's start (or the last DNS answer)
//! as `domainLookupEnd` folds connection-phase latency into the DNS phase.

mod common;
use common::*;

use std::time::Duration;

use happy_eyeballs::{ConnectionAttemptHttpVersions, ConnectionResult, Id, Input, Output};

/// A arrives at t=0, AAAA at t=10ms, HTTPS (h3+h2) at t=20ms. HTTP/3 and IPv6
/// attempts fail; the HTTP/2 attempt to the IPv4 address (from the A record)
/// wins. The reported lookup must end at t=0, when the A record arrived, even
/// though the winning connection only starts at t=20ms.
#[test]
fn dns_timing_anchored_to_resolving_record_not_connection_start() {
    let (t0, mut he) = setup();

    // HTTPS (id0), AAAA (id1) and A (id2) are all issued at t0.
    expect_initial_dns_queries(&mut he, t0);

    let a_received = t0;
    he.input(in_dns_a_positive(Id::from(2)), a_received);
    he.expect(out_resolution_delay(), a_received);

    let aaaa_received = t0 + Duration::from_millis(10);
    he.input(in_dns_aaaa_positive(Id::from(1)), aaaa_received);

    let https_received = t0 + Duration::from_millis(20);
    he.input(in_dns_https_positive(Id::from(0)), https_received);

    // Race the connections: every HTTP/3 attempt and every IPv6 attempt fails,
    // the HTTP/2 attempt to the IPv4 address succeeds.
    let mut now = https_received;
    let winning_attempt_start;
    loop {
        match he.process_output(now) {
            Some(Output::AttemptConnection { id, endpoint, .. }) => {
                let is_h2_v4 = endpoint.address.is_ipv4()
                    && endpoint.http_version == ConnectionAttemptHttpVersions::H2;
                if is_h2_v4 {
                    winning_attempt_start = now;
                    he.input(in_connection_result_positive(id), now);
                    break;
                }
                he.input(
                    Input::ConnectionResult {
                        id,
                        result: ConnectionResult::Failure("blackhole".to_string()),
                    },
                    now,
                );
            }
            Some(Output::Timer { duration }) => now += duration,
            other => panic!("unexpected output before success: {other:?}"),
        }
    }

    let timing = he.dns_timing().expect("a connection has succeeded");

    // domainLookupStart/End come from the A query: issued at t0, answered at t=0.
    assert_eq!(timing.start, t0);
    assert_eq!(timing.end, a_received);

    // The winning connection only started once the slower HTTPS answer arrived
    // and the HTTP/3 / IPv6 attempts had failed. That gap is connection time,
    // not DNS time, and must sit outside the lookup interval.
    assert!(timing.end < winning_attempt_start);
    assert!(winning_attempt_start - timing.end >= Duration::from_millis(20));
}

/// Before any connection succeeds there is nothing to report.
#[test]
fn dns_timing_none_until_a_connection_succeeds() {
    let (now, mut he) = setup();

    expect_initial_dns_queries(&mut he, now);
    assert_eq!(None, he.dns_timing());

    he.input(in_dns_a_positive(Id::from(2)), now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_https_positive(Id::from(0)), now);
    assert_eq!(None, he.dns_timing());
}
