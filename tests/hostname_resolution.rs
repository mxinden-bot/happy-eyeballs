/// > 4. Hostname Resolution
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4>
mod common;
use common::*;

use std::{net::SocketAddr, time::Duration};

use happy_eyeballs::{
    ConnectionAttemptHttpVersions, DnsRecordType, DnsResult, Endpoint, FailureReason, HttpVersions,
    Id, Input, IpPreference, NetworkConfig, Output, RESOLUTION_DELAY,
};

/// Drives the standard opening burst, feeds `https_input`, then asserts the
/// expected attempt fires after the resolution delay. `https_input` and
/// `expected_attempt` are builders parameterized by the relevant id.
fn expect_hints_move_on_with_timeout(
    s: &mut Scenario,
    https_input: fn(Id) -> Input,
    expected_attempt: fn(Id) -> Output,
) {
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(https_input(https), out_resolution_delay());
    s.advance(RESOLUTION_DELAY).output(expected_attempt(attempt));
}

#[test]
fn initial_state() {
    let mut s = Scenario::new();
    let https = s.next_id();

    s.output(out_send_dns_https(https));
}

/// > All of the DNS queries SHOULD be made as soon after one another as
/// > possible. The order in which the queries are sent SHOULD be as follows
/// > (omitting any query that doesn't apply based on the logic described
/// > above):
/// >
/// > 1. SVCB or HTTPS query
/// > 2. AAAA query
/// > 3. A query
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.1>
#[test]
fn sendig_dns_queries() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a));
}

/// > Implementations SHOULD NOT wait for all answers to return before
/// > starting the next steps of connection establishment.
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
#[test]
fn dont_wait_for_all_dns_answers() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h3(v6_attempt));
}

/// > The client moves onto sorting addresses and establishing
/// > connections once one of the following condition sets is met:
/// >
/// > Either:
/// >
/// > - Some positive (non-empty) address answers have been received AND
/// > - A postive (non-empty) or negative (empty) answer has been
/// >   received for the preferred address family that was queried AND
/// > - SVCB/HTTPS service information has been received (or has received a negative response)
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
#[test]
fn move_on_non_timeout() {
    #[derive(Debug)]
    struct Case {
        address_family: NetworkConfig,
        positive: Input,
        preferred: Option<Input>,
        expected: Option<Output>,
    }

    // Ids are identical across cases (each case drives a fresh machine).
    let mut ids = IdSeq::new();
    let (https, aaaa, a) = (ids.next_id(), ids.next_id(), ids.next_id());
    let attempt = ids.next_id();

    let test_cases = vec![
        // V6 preferred, V6 positive, HTTPS positive, expect V6 connection attempt
        Case {
            address_family: NetworkConfig {
                http_versions: HttpVersions::default(),
                ip: IpPreference::DualStackPreferV6,
                ..NetworkConfig::default()
            },
            positive: in_dns_aaaa_positive(aaaa),
            preferred: None,
            expected: Some(out_attempt_v6_h1_h2(attempt)),
        },
        // V6 preferred, V4 positive, V6 positive, HTTPS positive, expect V6 connection attempt
        Case {
            address_family: NetworkConfig {
                http_versions: HttpVersions::default(),
                ip: IpPreference::DualStackPreferV6,
                ..NetworkConfig::default()
            },
            positive: in_dns_a_positive(a),
            preferred: Some(in_dns_aaaa_positive(aaaa)),
            expected: Some(out_attempt_v6_h1_h2(attempt)),
        },
        // V6 preferred, V6 negative, V4 positive, HTTPS positive, expect V4 connection attempt
        Case {
            address_family: NetworkConfig {
                http_versions: HttpVersions::default(),
                ip: IpPreference::DualStackPreferV6,
                ..NetworkConfig::default()
            },
            positive: in_dns_a_positive(a),
            preferred: Some(in_dns_aaaa_negative(aaaa)),
            expected: Some(out_attempt_v4_h1_h2(attempt)),
        },
        // V4 preferred, V4 positive, HTTPS positive, expect V4 connection attempt
        Case {
            address_family: NetworkConfig {
                http_versions: HttpVersions::default(),
                ip: IpPreference::DualStackPreferV4,
                ..NetworkConfig::default()
            },
            positive: in_dns_a_positive(a),
            preferred: None,
            expected: Some(out_attempt_v4_h1_h2(attempt)),
        },
        // V4 preferred, V6 positive, V4 positive, HTTPS positive, expect V4 connection attempt
        Case {
            address_family: NetworkConfig {
                http_versions: HttpVersions::default(),
                ip: IpPreference::DualStackPreferV4,
                ..NetworkConfig::default()
            },
            positive: in_dns_aaaa_positive(aaaa),
            preferred: Some(in_dns_a_positive(a)),
            expected: Some(out_attempt_v4_h1_h2(attempt)),
        },
        // V4 preferred, V4 negative, V6 positive, HTTPS positive, expect V6 connection attempt
        Case {
            address_family: NetworkConfig {
                http_versions: HttpVersions::default(),
                ip: IpPreference::DualStackPreferV4,
                ..NetworkConfig::default()
            },
            positive: in_dns_aaaa_positive(aaaa),
            preferred: Some(in_dns_a_negative(a)),
            expected: Some(out_attempt_v6_h1_h2(attempt)),
        },
    ];

    for test_case in test_cases {
        for https_variant in [
            in_dns_https_positive_no_alpn(https),
            in_dns_https_negative(https),
        ] {
            let mut s = Scenario::with_config(test_case.address_family.clone());

            s.output(out_send_dns_https(https))
                .output(out_send_dns_aaaa(aaaa))
                .output(out_send_dns_a(a))
                .feed(test_case.positive.clone(), out_resolution_delay());

            match test_case.preferred.clone() {
                Some(preferred) => {
                    s.feed(preferred, out_resolution_delay());
                }
                None => {
                    s.output(out_resolution_delay());
                }
            }

            match test_case.expected.clone() {
                Some(expected) => {
                    s.feed(https_variant, expected);
                }
                None => {
                    s.feed_idle(https_variant);
                }
            }
        }
    }
}

/// > Or:
/// >
/// > - Some positive (non-empty) address answers have been received AND
/// > - A resolution time delay has passed after which other answers have not been received
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
// TODO: Other combinations
#[test]
fn move_on_timeout() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v4_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_a_positive(a), out_resolution_delay());

    s.advance(RESOLUTION_DELAY)
        .output(out_attempt_v4_h1_h2(v4_attempt));
}

/// > Resolution Delay (Section 4): The time to wait for a AAAA record after
/// > receiving an A record. Recommended to be 50 milliseconds.
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-9>
#[test]
fn resolution_delay_starts_after_other_response() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v4_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // No other response received yet.
        .idle()
        .feed(in_dns_a_positive(a), out_resolution_delay());

    s.advance(RESOLUTION_DELAY)
        .output(out_attempt_v4_h1_h2(v4_attempt));
}

/// Start of the Resolution Delay is not the first DNS query is sent, but
/// the first response received.
///
/// > A resolution time delay has passed after which other answers have not been received
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2>
#[test]
fn resolution_delay_starts_on_first_response() {
    const RESPONSE_DELAY: Duration = Duration::from_millis(10);
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v4_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // No other response received yet.
        .idle();

    // Receive first response, thus activating the resolution delay.
    s.advance(RESPONSE_DELAY)
        .feed(in_dns_a_positive(a), out_resolution_delay());

    // Resolution delay is off of the response, not the query start.
    s.advance(RESOLUTION_DELAY - RESPONSE_DELAY)
        .output(Output::Timer {
            duration: RESPONSE_DELAY,
        });

    s.advance(RESPONSE_DELAY)
        .output(out_attempt_v4_h1_h2(v4_attempt));
}

/// > ServiceMode records can contain address hints via ipv6hint and
/// > ipv4hint parameters. When these are received, they SHOULD be
/// > considered as positive non-empty answers for the purpose of the
/// > algorithm when A and AAAA records corresponding to the TargetName
/// > are not available yet.
///
/// HTTPS arrives first with both v6 and v4 hints while AAAA and A are still
/// in-flight. After the resolution timeout the v6 hint is used. When AAAA
/// and A subsequently arrive with negative answers, both hints are discarded
/// — a negative answer replaces hints per the draft: "when those records are
/// received, they replace the hints". After the in-flight v6 attempt fails,
/// no v4 attempt follows (v4 hint was discarded when A returned negative).
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
#[test]
fn https_hints() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_v4_and_v6_hints(https), out_resolution_delay());

    s.advance(RESOLUTION_DELAY)
        .output(out_attempt_v6_h3(v6_attempt))
        .output(out_connection_attempt_delay())
        // AAAA and A arrive negative: both hints are discarded. The
        // connection attempt delay is re-emitted while the in-flight
        // v6 attempt is still pending.
        .feed(in_dns_aaaa_negative(aaaa), out_connection_attempt_delay())
        .feed(in_dns_a_negative(a), out_connection_attempt_delay())
        // The v6 attempt fails. No v4 retry — v4 hint was discarded when
        // A returned a negative answer.
        .feed(
            in_connection_result_negative(v6_attempt),
            Output::Failed(FailureReason::Connection),
        );
}

/// HTTPS IP hints should count as positive address answers for the
/// resolution delay timeout path (`move_on_with_timeout`).
///
/// Scenario: only HTTPS with v6 hints has arrived, AAAA and A are still
/// in-progress. After the resolution delay we should move on.
///
/// <https://github.com/mozilla/happy-eyeballs/issues/39>
#[test]
fn https_hints_move_on_with_timeout() {
    let mut s = Scenario::new();
    expect_hints_move_on_with_timeout(
        &mut s,
        in_dns_https_positive_v6_hints,
        out_attempt_v6_h3,
    );
}

/// HTTPS IPv4 hints should also count for `move_on_with_timeout`.
///
/// Mirrors `https_hints_move_on_with_timeout` but using IPv4 hints instead of IPv6.
#[test]
fn https_v4_hints_move_on_with_timeout() {
    let mut s = Scenario::new();
    expect_hints_move_on_with_timeout(
        &mut s,
        in_dns_https_positive_v4_hints,
        out_attempt_v4_h3,
    );
}

/// When the resolution delay has exactly elapsed, `process_output` returns `None`,
/// not a zero-duration timer.
#[test]
fn resolution_delay_boundary() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v4_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // HTTPS negative and A positive arrive at T; AAAA still pending.
        .feed(in_dns_https_negative(https), out_resolution_delay())
        .feed(in_dns_a_positive(a), out_resolution_delay());

    // Resolution delay has elapsed; move_on_with_timeout fires.
    s.advance(RESOLUTION_DELAY)
        .output(out_attempt_v4_h1_h2(v4_attempt))
        // Connection fails immediately. AAAA still pending, resolution delay
        // exactly expired — no timer, just None.
        .feed_idle(in_connection_result_negative(v4_attempt));
}

/// > Note that clients are still required to issue A and AAAA queries
/// > for those TargetNames if they haven't yet received those records.
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-4.2.1>
#[test]
fn https_hints_still_query_a_aaaa() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let svc1 = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_svc1(https), out_send_dns_svc1(svc1));
}

#[test]
fn https_h3_upgrade_without_hints() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_aaaa_positive(aaaa), out_resolution_delay())
        .feed(in_dns_https_positive(https), out_attempt_v6_h3(v6_attempt));
}

/// A ServiceInfo advertising H3 must not produce an H3 connection attempt
/// when H3 is disabled in the network config.
#[test]
fn https_h3_disabled() {
    let mut s = Scenario::with_config(NetworkConfig {
        http_versions: HttpVersions {
            h1: true,
            h2: true,
            h3: false,
        },
        ..NetworkConfig::default()
    });
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_aaaa_positive(aaaa), out_resolution_delay())
        .feed(in_dns_https_positive(https), out_attempt_v6_h2(v6_attempt));
}

#[test]
fn multiple_ips_per_record() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_negative(https), out_resolution_delay())
        .feed(in_dns_a_negative(a), out_resolution_delay())
        .feed(
            Input::DnsResult {
                id: aaaa,
                result: DnsResult::Aaaa(Ok(vec![V6_ADDR, V6_ADDR_2, V6_ADDR_3])),
            },
            out_attempt_v6_h1_h2(attempt_1),
        )
        .tick()
        .output(Output::AttemptConnection {
            id: attempt_2,
            endpoint: Endpoint {
                address: SocketAddr::new(V6_ADDR_2.into(), PORT),
                http_version: ConnectionAttemptHttpVersions::H2OrH1,
                ech_config: None,
            },
            is_ech_retry: false,
        });
}

/// On a single-stack network, the state machine should skip querying the
/// disabled address family. IPv4-only skips AAAA, IPv6-only skips A.
#[test]
fn single_stack_skips_disabled_address_family() {
    struct Case {
        ip: IpPreference,
        expected_dns_query: fn(Id) -> Output,
        dns_response: fn(Id) -> Input,
        expected_connection: fn(Id) -> Output,
    }

    let cases = vec![
        Case {
            ip: IpPreference::Ipv4Only,
            expected_dns_query: out_send_dns_a,
            dns_response: in_dns_a_positive,
            expected_connection: out_attempt_v4_h1_h2,
        },
        Case {
            ip: IpPreference::Ipv6Only,
            expected_dns_query: out_send_dns_aaaa,
            dns_response: in_dns_aaaa_positive,
            expected_connection: out_attempt_v6_h1_h2,
        },
    ];

    for case in cases {
        let mut s = Scenario::with_config(NetworkConfig {
            ip: case.ip,
            ..NetworkConfig::default()
        });
        let (https, family, attempt) = (s.next_id(), s.next_id(), s.next_id());

        s.output(out_send_dns_https(https))
            // Should skip the disabled address family query.
            .output((case.expected_dns_query)(family))
            .feed(in_dns_https_negative(https), out_resolution_delay())
            .feed((case.dns_response)(family), (case.expected_connection)(attempt));
    }
}

/// On a single-stack network, target-name follow-up queries must also skip
/// the disabled address family.
///
/// <https://github.com/mozilla/happy-eyeballs/issues/38>
#[test]
fn single_stack_target_name_skips_disabled_address_family() {
    /// The only address-family query sent for the target name (A variant).
    fn out_send_dns_svc1_a(id: Id) -> Output {
        Output::SendDnsQuery {
            id,
            hostname: SVC1.into(),
            record_type: DnsRecordType::A,
        }
    }

    struct Case {
        ip: IpPreference,
        /// The only address-family query sent for the origin domain.
        origin_dns_query: fn(Id) -> Output,
        /// The only address-family query sent for the target name.
        target_name_dns_query: fn(Id) -> Output,
    }

    let cases = vec![
        Case {
            ip: IpPreference::Ipv6Only,
            origin_dns_query: out_send_dns_aaaa,
            target_name_dns_query: out_send_dns_svc1,
        },
        Case {
            ip: IpPreference::Ipv4Only,
            origin_dns_query: out_send_dns_a,
            target_name_dns_query: out_send_dns_svc1_a,
        },
    ];

    for case in cases {
        let mut s = Scenario::with_config(NetworkConfig {
            ip: case.ip,
            ..NetworkConfig::default()
        });
        let (https, origin, target) = (s.next_id(), s.next_id(), s.next_id());

        s.output(out_send_dns_https(https))
            .output((case.origin_dns_query)(origin))
            .feed(
                in_dns_https_positive_svc1(https),
                (case.target_name_dns_query)(target),
            )
            // No query for the disabled address family should appear,
            // only the resolution delay.
            .output(out_resolution_delay());
    }
}
