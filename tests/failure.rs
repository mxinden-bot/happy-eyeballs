mod common;
use common::*;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use happy_eyeballs::{
    ConnectionAttemptHttpVersions, Endpoint, FailureReason, HappyEyeballs, Output,
};

/// All DNS queries fail. No connections are attempted.
#[test]
fn all_dns_failed() {
    let (now, mut he) = setup();
    let mut ids = IdSeq::new();
    let (https, aaaa, a) = (ids.next_id(), ids.next_id(), ids.next_id());

    he.expect(
        vec![
            (None, Some(out_send_dns_https(https))),
            (None, Some(out_send_dns_aaaa(aaaa))),
            (None, Some(out_send_dns_a(a))),
            (
                Some(in_dns_https_negative(https)),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_aaaa_negative(aaaa)),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_a_negative(a)),
                Some(Output::Failed(FailureReason::DnsResolution)),
            ),
        ],
        now,
    );
}

/// DNS partially fails (HTTPS and A fail) but AAAA succeeds, then connection fails.
#[test]
fn dns_partial_failure_then_connection_failed() {
    let (now, mut he) = setup();
    let mut ids = IdSeq::new();
    let (https, aaaa, a) = (ids.next_id(), ids.next_id(), ids.next_id());
    let v6_attempt = ids.next_id();

    he.expect(
        vec![
            (None, Some(out_send_dns_https(https))),
            (None, Some(out_send_dns_aaaa(aaaa))),
            (None, Some(out_send_dns_a(a))),
            (
                Some(in_dns_https_negative(https)),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_aaaa_positive(aaaa)),
                Some(out_attempt_v6_h1_h2(v6_attempt)),
            ),
            (
                Some(in_dns_a_negative(a)),
                Some(out_connection_attempt_delay()),
            ),
            (
                Some(in_connection_result_negative(v6_attempt)),
                Some(Output::Failed(FailureReason::Connection)),
            ),
        ],
        now,
    );
}

/// All DNS succeeds but all connection attempts fail.
#[test]
fn all_connections_failed() {
    let (now, mut he) = setup();
    let mut ids = IdSeq::new();
    let (https, aaaa, a) = (ids.next_id(), ids.next_id(), ids.next_id());
    let (v6_attempt, v4_attempt) = (ids.next_id(), ids.next_id());

    he.expect(
        vec![
            (None, Some(out_send_dns_https(https))),
            (None, Some(out_send_dns_aaaa(aaaa))),
            (None, Some(out_send_dns_a(a))),
            (
                Some(in_dns_https_positive_no_alpn(https)),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_aaaa_positive(aaaa)),
                Some(out_attempt_v6_h1_h2(v6_attempt)),
            ),
            (
                Some(in_dns_a_positive(a)),
                Some(out_connection_attempt_delay()),
            ),
            (
                Some(in_connection_result_negative(v6_attempt)),
                Some(out_attempt_v4_h1_h2(v4_attempt)),
            ),
            (
                Some(in_connection_result_negative(v4_attempt)),
                Some(Output::Failed(FailureReason::Connection)),
            ),
        ],
        now,
    );
}

/// When the target is an IP address and the connection fails, the state
/// machine must report `Failed(Connection)` instead of retrying the same
/// endpoint indefinitely.
#[test]
fn ip_host_connection_failure() {
    let now = std::time::Instant::now();
    let mut he = HappyEyeballs::new("127.0.0.1", PORT).unwrap();
    let mut ids = IdSeq::new();
    let conn = ids.next_id();

    he.expect(
        vec![
            (
                None,
                Some(Output::AttemptConnection {
                    id: conn,
                    endpoint: Endpoint {
                        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), PORT),
                        http_version: ConnectionAttemptHttpVersions::H2OrH1,
                        ech_config: None,
                    },
                    is_ech_retry: false,
                }),
            ),
            (
                Some(in_connection_result_negative(conn)),
                Some(Output::Failed(FailureReason::Connection)),
            ),
        ],
        now,
    );
}

/// First connection fails, second succeeds. Should not emit `Failed`.
#[test]
fn first_connection_fails_second_succeeds() {
    let (now, mut he) = setup();
    let mut ids = IdSeq::new();
    let (https, aaaa, a) = (ids.next_id(), ids.next_id(), ids.next_id());
    let (v6_attempt, v4_attempt) = (ids.next_id(), ids.next_id());

    he.expect(
        vec![
            (None, Some(out_send_dns_https(https))),
            (None, Some(out_send_dns_aaaa(aaaa))),
            (None, Some(out_send_dns_a(a))),
            (
                Some(in_dns_https_positive_no_alpn(https)),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_aaaa_positive(aaaa)),
                Some(out_attempt_v6_h1_h2(v6_attempt)),
            ),
            (
                Some(in_dns_a_positive(a)),
                Some(out_connection_attempt_delay()),
            ),
            (
                Some(in_connection_result_negative(v6_attempt)),
                Some(out_attempt_v4_h1_h2(v4_attempt)),
            ),
            (
                Some(in_connection_result_positive(v4_attempt)),
                Some(Output::Succeeded),
            ),
        ],
        now,
    );
}
