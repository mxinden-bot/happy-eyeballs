mod common;
use common::*;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use happy_eyeballs::{ConnectionAttemptHttpVersions, Endpoint, FailureReason, Output};

/// All DNS queries fail. No connections are attempted.
#[test]
fn all_dns_failed() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_negative(https), out_resolution_delay())
        .feed(in_dns_aaaa_negative(aaaa), out_resolution_delay())
        .feed(
            in_dns_a_negative(a),
            Output::Failed(FailureReason::DnsResolution),
        );
}

/// DNS partially fails (HTTPS and A fail) but AAAA succeeds, then connection fails.
#[test]
fn dns_partial_failure_then_connection_failed() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_negative(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt))
        .feed(in_dns_a_negative(a), out_connection_attempt_delay())
        .feed(
            in_connection_result_negative(v6_attempt),
            Output::Failed(FailureReason::Connection),
        );
}

/// All DNS succeeds but all connection attempts fail.
#[test]
fn all_connections_failed() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (v6_attempt, v4_attempt) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_no_alpn(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt))
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        .feed(
            in_connection_result_negative(v6_attempt),
            out_attempt_v4_h1_h2(v4_attempt),
        )
        .feed(
            in_connection_result_negative(v4_attempt),
            Output::Failed(FailureReason::Connection),
        );
}

/// When the target is an IP address and the connection fails, the state
/// machine must report `Failed(Connection)` instead of retrying the same
/// endpoint indefinitely.
#[test]
fn ip_host_connection_failure() {
    let mut s = Scenario::with_host("127.0.0.1");
    let conn = s.next_id();

    s.output(Output::AttemptConnection {
        id: conn,
        endpoint: Endpoint {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), PORT),
            http_version: ConnectionAttemptHttpVersions::H2OrH1,
            ech_config: None,
        },
        is_ech_retry: false,
    })
    .feed(
        in_connection_result_negative(conn),
        Output::Failed(FailureReason::Connection),
    );
}

/// First connection fails, second succeeds. Should not emit `Failed`.
#[test]
fn first_connection_fails_second_succeeds() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (v6_attempt, v4_attempt) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_no_alpn(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt))
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        .feed(
            in_connection_result_negative(v6_attempt),
            out_attempt_v4_h1_h2(v4_attempt),
        )
        .feed(in_connection_result_positive(v4_attempt), Output::Succeeded);
}
