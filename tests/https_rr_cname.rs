//! Tests for the HTTPS-RR / CNAME consistency check.
//!
//! When the origin's A/AAAA resolution reports a canonical name, an HTTPS
//! record whose `TargetName` is inconsistent with that canonical name is
//! dropped, and the connection prefers the origin's plain A/AAAA addresses.
//! This behaviour was originally introduced in Firefox to prevent broken ECH
//! handshakes when dual-CDN steering points the HTTPS record at one CDN while
//! the A/AAAA CNAME chain steers to another.

mod common;
use common::*;

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use happy_eyeballs::{
    ConnectionResult, DnsRecordType, DnsResult, Endpoint, HappyEyeballs, HttpVersion, Id, Input,
    NetworkConfig, Output,
};

/// HTTPS record `TargetName`: a CDN distinct from the origin, carrying ECH.
const CDN_A: &str = "cdn-a.example.net.";
/// A different CDN the origin's CNAME chain might steer to.
const CDN_B: &str = "cdn-b.example.net.";

/// Origin (example.com) addresses, reached via the plain A/AAAA / CNAME path.
const ORIGIN_V6: Ipv6Addr = V6_ADDR;
const ORIGIN_V4: Ipv4Addr = V4_ADDR;
/// Addresses the HTTPS record's TargetName (CDN_A) resolves to.
const CDN_A_V6: Ipv6Addr = V6_ADDR_2;
const CDN_A_V4: Ipv4Addr = V4_ADDR_2;

/// A single ECH-bearing HTTPS record pointing at `target`.
fn https_ech_record(target: &str) -> DnsResult {
    DnsResult::Https(Ok(vec![
        service_info(1, target, &[HttpVersion::H2, HttpVersion::H3]).ech(),
    ]))
}

/// Case- and trailing-dot-insensitive name comparison, matching the crate's
/// own normalization, used by the test answer functions.
fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// Drive the state machine to completion, answering each DNS query via
/// `answer` (in the order the machine emits them) and failing every connection
/// attempt so the next is produced. Returns the endpoints that were attempted.
fn run(config: NetworkConfig, answer: impl Fn(&str, DnsRecordType) -> DnsResult) -> Vec<Endpoint> {
    let mut now = Instant::now();
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();
    collect_attempts(&mut he, &mut now, Some(&answer))
}

/// Answers a DNS query for `(hostname, record_type)` with a [`DnsResult`].
type AnswerFn<'a> = &'a dyn Fn(&str, DnsRecordType) -> DnsResult;

/// Drive the machine, advancing timers, collecting connection attempts (failing
/// each), and optionally answering DNS queries via `answer`. Stops when the
/// machine stalls, succeeds, fails, or (when `answer` is `None`) emits an
/// unanswered DNS query.
fn collect_attempts(
    he: &mut HappyEyeballs,
    now: &mut Instant,
    answer: Option<AnswerFn>,
) -> Vec<Endpoint> {
    let mut attempts = Vec::new();
    for _ in 0..10_000 {
        match he.process_output(*now) {
            Some(Output::AttemptConnection { id, endpoint, .. }) => {
                attempts.push(endpoint);
                he.process_input(
                    Input::ConnectionResult {
                        id,
                        result: ConnectionResult::Failure("fail".to_string()),
                    },
                    *now,
                );
            }
            Some(Output::Timer { duration }) => *now += duration,
            Some(Output::CancelConnection { .. }) => {}
            Some(Output::SendDnsQuery {
                id,
                hostname,
                record_type,
            }) => {
                let Some(answer) = answer else {
                    break;
                };
                let hostname: String = hostname.into();
                let result = answer(&hostname, record_type);
                he.process_input(Input::DnsResult { id, result }, *now);
            }
            Some(Output::Succeeded) | Some(Output::Failed(_)) | None => break,
        }
    }
    attempts
}

fn attempted_addrs(endpoints: &[Endpoint]) -> HashSet<IpAddr> {
    endpoints.iter().map(|e| e.address.ip()).collect()
}

fn any_ech(endpoints: &[Endpoint]) -> bool {
    endpoints.iter().any(|e| e.ech_config.is_some())
}

fn all_ech(endpoints: &[Endpoint]) -> bool {
    !endpoints.is_empty() && endpoints.iter().all(|e| e.ech_config.is_some())
}

/// Answer function: origin resolves with canonical name `origin_cname`; the
/// HTTPS TargetName CDN_A resolves to its own addresses.
fn answer_with_origin_cname(
    origin_cname: Option<&'static str>,
) -> impl Fn(&str, DnsRecordType) -> DnsResult {
    move |hostname: &str, record_type: DnsRecordType| {
        let cname = origin_cname.map(|c| c.into());
        match record_type {
            DnsRecordType::Https => https_ech_record(CDN_A),
            DnsRecordType::Aaaa if same_name(hostname, HOSTNAME) => {
                DnsResult::Aaaa(Ok(vec![ORIGIN_V6]), cname)
            }
            DnsRecordType::A if same_name(hostname, HOSTNAME) => {
                DnsResult::A(Ok(vec![ORIGIN_V4]), cname)
            }
            DnsRecordType::Aaaa if same_name(hostname, CDN_A) => {
                DnsResult::Aaaa(Ok(vec![CDN_A_V6]), None)
            }
            DnsRecordType::A if same_name(hostname, CDN_A) => {
                DnsResult::A(Ok(vec![CDN_A_V4]), None)
            }
            DnsRecordType::Aaaa => DnsResult::Aaaa(Err(()), None),
            DnsRecordType::A => DnsResult::A(Err(()), None),
        }
    }
}

/// Matching CNAME: the origin steers to the same CDN the HTTPS record points
/// at, so the record is used (ECH endpoints at the CDN's addresses).
#[test]
fn matching_cname_record_used() {
    let attempts = run(
        NetworkConfig::default(),
        answer_with_origin_cname(Some(CDN_A)),
    );

    assert_eq!(
        attempted_addrs(&attempts),
        HashSet::from([CDN_A_V6.into(), CDN_A_V4.into()]),
    );
    assert!(
        all_ech(&attempts),
        "ECH must be carried to the CDN endpoints"
    );
}

/// Mismatching CNAME: the origin steers (via CNAME) to a different CDN than the
/// HTTPS record's TargetName. The record is dropped and we connect to the
/// origin's plain A/AAAA addresses without ECH ("prefer the CNAME").
#[test]
fn mismatching_cname_record_dropped() {
    let attempts = run(
        NetworkConfig::default(),
        answer_with_origin_cname(Some(CDN_B)),
    );

    assert_eq!(
        attempted_addrs(&attempts),
        HashSet::from([ORIGIN_V6.into(), ORIGIN_V4.into()]),
    );
    assert!(
        !any_ech(&attempts),
        "the broken ECH target must not be attempted"
    );
    let cdn: HashSet<IpAddr> = HashSet::from([CDN_A_V6.into(), CDN_A_V4.into()]);
    assert!(
        attempted_addrs(&attempts).is_disjoint(&cdn),
        "the CDN behind the dropped record must never be attempted"
    );
}

/// No canonical name reported by the origin resolution: no filtering, the
/// record is used (mirrors legacy "empty cname => record stays usable").
#[test]
fn empty_cname_no_filtering() {
    let attempts = run(NetworkConfig::default(), answer_with_origin_cname(None));

    assert_eq!(
        attempted_addrs(&attempts),
        HashSet::from([CDN_A_V6.into(), CDN_A_V4.into()]),
    );
    assert!(all_ech(&attempts));
}

/// Case- and trailing-dot-insensitive matching: the HTTPS TargetName and the
/// reported canonical name differ only in case and trailing dot, yet match.
#[test]
fn cname_match_is_case_and_trailing_dot_insensitive() {
    let target = "CDN-A.Example.NET"; // mixed case, no trailing dot
    let origin_cname = "cdn-a.example.net."; // lower case, trailing dot

    let attempts = run(
        NetworkConfig::default(),
        move |hostname: &str, record_type| match record_type {
            DnsRecordType::Https => https_ech_record(target),
            DnsRecordType::Aaaa if same_name(hostname, HOSTNAME) => {
                DnsResult::Aaaa(Ok(vec![ORIGIN_V6]), Some(origin_cname.into()))
            }
            DnsRecordType::A if same_name(hostname, HOSTNAME) => {
                DnsResult::A(Ok(vec![ORIGIN_V4]), Some(origin_cname.into()))
            }
            DnsRecordType::Aaaa if same_name(hostname, target) => {
                DnsResult::Aaaa(Ok(vec![CDN_A_V6]), None)
            }
            DnsRecordType::A if same_name(hostname, target) => {
                DnsResult::A(Ok(vec![CDN_A_V4]), None)
            }
            DnsRecordType::Aaaa => DnsResult::Aaaa(Err(()), None),
            DnsRecordType::A => DnsResult::A(Err(()), None),
        },
    );

    assert_eq!(
        attempted_addrs(&attempts),
        HashSet::from([CDN_A_V6.into(), CDN_A_V4.into()]),
        "names matching modulo case/trailing-dot must be treated as consistent"
    );
    assert!(all_ech(&attempts));
}

/// A and AAAA report different canonical names. A ServiceInfo passes if its
/// TargetName matches EITHER family's canonical name. Here AAAA steers to
/// CDN_A (the record's target) while A steers to CDN_B, so the record is kept.
#[test]
fn passes_when_matching_either_address_family() {
    let attempts = run(NetworkConfig::default(), |hostname: &str, record_type| {
        match record_type {
            DnsRecordType::Https => https_ech_record(CDN_A),
            // AAAA canonical name matches the record's target.
            DnsRecordType::Aaaa if same_name(hostname, HOSTNAME) => {
                DnsResult::Aaaa(Ok(vec![ORIGIN_V6]), Some(CDN_A.into()))
            }
            // A canonical name does not.
            DnsRecordType::A if same_name(hostname, HOSTNAME) => {
                DnsResult::A(Ok(vec![ORIGIN_V4]), Some(CDN_B.into()))
            }
            DnsRecordType::Aaaa if same_name(hostname, CDN_A) => {
                DnsResult::Aaaa(Ok(vec![CDN_A_V6]), None)
            }
            DnsRecordType::A if same_name(hostname, CDN_A) => {
                DnsResult::A(Ok(vec![CDN_A_V4]), None)
            }
            DnsRecordType::Aaaa => DnsResult::Aaaa(Err(()), None),
            DnsRecordType::A => DnsResult::A(Err(()), None),
        }
    });

    assert_eq!(
        attempted_addrs(&attempts),
        HashSet::from([CDN_A_V6.into(), CDN_A_V4.into()]),
        "matching either family's canonical name keeps the record"
    );
    assert!(all_ech(&attempts));
}

/// Arrival order: origin A/AAAA (with the mismatching canonical name) arrive
/// BEFORE the HTTPS record. The record is filtered as soon as it arrives.
#[test]
fn order_origin_before_https_filters_record() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, NetworkConfig::default()).unwrap();

    expect_query(&mut he, now, 0, HOSTNAME, DnsRecordType::Https);
    expect_query(&mut he, now, 1, HOSTNAME, DnsRecordType::Aaaa);
    expect_query(&mut he, now, 2, HOSTNAME, DnsRecordType::A);

    // Origin A/AAAA first, reporting the mismatching canonical name.
    he.process_input(
        Input::DnsResult {
            id: Id::from(1),
            result: DnsResult::Aaaa(Ok(vec![ORIGIN_V6]), Some(CDN_B.into())),
        },
        now,
    );
    he.process_input(
        Input::DnsResult {
            id: Id::from(2),
            result: DnsResult::A(Ok(vec![ORIGIN_V4]), Some(CDN_B.into())),
        },
        now,
    );
    // HTTPS record arrives last; it is inconsistent with the known CNAME.
    he.process_input(
        Input::DnsResult {
            id: Id::from(0),
            result: https_ech_record(CDN_A),
        },
        now,
    );

    let attempts = collect_attempts(&mut he, &mut now, None);
    assert_eq!(
        attempted_addrs(&attempts),
        HashSet::from([ORIGIN_V6.into(), ORIGIN_V4.into()]),
    );
    assert!(!any_ech(&attempts));
}

/// Arrival order: the HTTPS record arrives BEFORE the origin A/AAAA, so the
/// canonical name is not yet known and the target is fanned out. Once the
/// origin A/AAAA arrive with the mismatching canonical name, the record is
/// filtered retroactively and we prefer the origin addresses.
#[test]
fn order_https_before_origin_filters_record_retroactively() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, NetworkConfig::default()).unwrap();

    expect_query(&mut he, now, 0, HOSTNAME, DnsRecordType::Https);
    expect_query(&mut he, now, 1, HOSTNAME, DnsRecordType::Aaaa);
    expect_query(&mut he, now, 2, HOSTNAME, DnsRecordType::A);

    // HTTPS first: with no canonical name yet, the target is treated as usable
    // and gets fanned out (ids 3, 4).
    he.process_input(
        Input::DnsResult {
            id: Id::from(0),
            result: https_ech_record(CDN_A),
        },
        now,
    );
    expect_query(&mut he, now, 3, CDN_A, DnsRecordType::Aaaa);
    expect_query(&mut he, now, 4, CDN_A, DnsRecordType::A);

    // Origin A/AAAA arrive with the mismatching canonical name.
    he.process_input(
        Input::DnsResult {
            id: Id::from(1),
            result: DnsResult::Aaaa(Ok(vec![ORIGIN_V6]), Some(CDN_B.into())),
        },
        now,
    );
    he.process_input(
        Input::DnsResult {
            id: Id::from(2),
            result: DnsResult::A(Ok(vec![ORIGIN_V4]), Some(CDN_B.into())),
        },
        now,
    );
    // The (now irrelevant) target answers complete too.
    he.process_input(
        Input::DnsResult {
            id: Id::from(3),
            result: DnsResult::Aaaa(Err(()), None),
        },
        now,
    );
    he.process_input(
        Input::DnsResult {
            id: Id::from(4),
            result: DnsResult::A(Err(()), None),
        },
        now,
    );

    let attempts = collect_attempts(&mut he, &mut now, None);
    assert_eq!(
        attempted_addrs(&attempts),
        HashSet::from([ORIGIN_V6.into(), ORIGIN_V4.into()]),
        "the record is filtered retroactively once the CNAME is known"
    );
    assert!(!any_ech(&attempts));
    let cdn: HashSet<IpAddr> = HashSet::from([CDN_A_V6.into(), CDN_A_V4.into()]);
    assert!(attempted_addrs(&attempts).is_disjoint(&cdn));
}

/// HTTPS arrives first, an in-progress connection attempt to the CDN target is
/// started, then the origin AAAA arrives with a mismatching canonical name.
/// The in-progress attempt is NOT cancelled; the HTTPS record is ignored for
/// any subsequent attempts.
#[test]
fn in_progress_attempt_continues_after_retroactive_cname_filter() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, NetworkConfig::default()).unwrap();

    expect_query(&mut he, now, 0, HOSTNAME, DnsRecordType::Https);
    expect_query(&mut he, now, 1, HOSTNAME, DnsRecordType::Aaaa);
    expect_query(&mut he, now, 2, HOSTNAME, DnsRecordType::A);

    // HTTPS arrives first; fan out A/AAAA for CDN_A.
    he.process_input(
        Input::DnsResult {
            id: Id::from(0),
            result: https_ech_record(CDN_A),
        },
        now,
    );
    expect_query(&mut he, now, 3, CDN_A, DnsRecordType::Aaaa);
    expect_query(&mut he, now, 4, CDN_A, DnsRecordType::A);

    // CDN_A target resolves; once both addresses are available the machine
    // starts connecting immediately (no resolution-delay timer needed).
    he.process_input(
        Input::DnsResult {
            id: Id::from(3),
            result: DnsResult::Aaaa(Ok(vec![CDN_A_V6]), None),
        },
        now,
    );
    he.process_input(
        Input::DnsResult {
            id: Id::from(4),
            result: DnsResult::A(Ok(vec![CDN_A_V4]), None),
        },
        now,
    );

    // First connection attempt (CDN_A with ECH) — before mismatch is known.
    let first_attempt = match he.process_output(now) {
        Some(Output::AttemptConnection { id, endpoint, .. }) => {
            assert!(
                endpoint.ech_config.is_some(),
                "first attempt must carry ECH"
            );
            assert_eq!(
                endpoint.address.ip(),
                IpAddr::from(CDN_A_V6),
                "first attempt must target CDN_A"
            );
            id
        }
        other => panic!("expected AttemptConnection, got {other:?}"),
    };

    // Origin AAAA arrives with a mismatching CNAME — CDN_B, not CDN_A.
    he.process_input(
        Input::DnsResult {
            id: Id::from(1),
            result: DnsResult::Aaaa(Ok(vec![ORIGIN_V6]), Some(CDN_B.into())),
        },
        now,
    );

    // The in-progress CDN_A attempt must NOT be cancelled.
    let next = he.process_output(now);
    assert!(
        !matches!(&next, Some(Output::CancelConnection { id }) if *id == first_attempt),
        "in-progress attempt must not be cancelled on CNAME mismatch; got {next:?}"
    );

    // Finish feeding remaining DNS results and let the machine run to completion.
    he.process_input(
        Input::DnsResult {
            id: Id::from(2),
            result: DnsResult::A(Ok(vec![ORIGIN_V4]), Some(CDN_B.into())),
        },
        now,
    );

    // Fail the in-progress CDN_A attempt to let the machine advance.
    he.process_input(
        Input::ConnectionResult {
            id: first_attempt,
            result: ConnectionResult::Failure("fail".to_string()),
        },
        now,
    );

    // Remaining attempts (driven by collect_attempts) must use origin addresses only.
    let remaining = collect_attempts(&mut he, &mut now, None);
    let cdn: HashSet<IpAddr> = HashSet::from([CDN_A_V6.into(), CDN_A_V4.into()]);
    assert!(
        attempted_addrs(&remaining).is_disjoint(&cdn),
        "no further attempts must target the CDN after the CNAME mismatch"
    );
    assert!(
        !any_ech(&remaining),
        "subsequent attempts must not carry the dropped ECH record"
    );
}
