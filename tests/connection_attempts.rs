/// > 6. Establishing Connections
///
/// <https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-02.html#section-6>
mod common;
use common::*;

use std::{net::SocketAddr, time::Duration};

use happy_eyeballs::{
    ConnectionAttemptHttpVersions, DnsResult, Endpoint, Input, NetworkConfig, Output,
};

#[test]
fn ipv6_blackhole() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive(https), out_resolution_delay())
        .feed(in_dns_a_positive(a), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h3(v6_attempt));

    for _ in 0..42 {
        let attempt = s.tick().process().unwrap().attempt().unwrap();
        if attempt.address.is_ipv4() {
            return;
        }
    }

    panic!("Did not fall back to IPv4.");
}

#[test]
fn connection_attempt_delay() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (v6_attempt, v4_attempt) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_no_alpn(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt))
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        .tick()
        .output(out_attempt_v4_h1_h2(v4_attempt));
}

#[test]
fn never_try_same_attempt_twice() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_negative(https), out_resolution_delay())
        .feed(in_dns_a_negative(a), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt))
        .tick()
        .idle();
}

#[test]
fn successful_connection_cancels_others() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2, attempt_3) = (s.next_id(), s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_no_alpn(https), out_resolution_delay())
        .feed(
            Input::DnsResult {
                id: aaaa,
                result: DnsResult::Aaaa(Ok(vec![V6_ADDR, V6_ADDR_2])),
            },
            out_attempt_v6_h1_h2(attempt_1),
        )
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        .tick()
        .output(Output::AttemptConnection {
            id: attempt_2,
            endpoint: Endpoint {
                address: SocketAddr::new(V6_ADDR_2.into(), PORT),
                http_version: ConnectionAttemptHttpVersions::H2OrH1,
                ech_config: None,
            },
            is_ech_retry: false,
        })
        .tick()
        .output(out_attempt_v4_h1_h2(attempt_3))
        .feed(
            in_connection_result_positive(attempt_1),
            Output::CancelConnection { id: attempt_2 },
        )
        .output(Output::CancelConnection { id: attempt_3 })
        .output(Output::Succeeded);
}

#[test]
fn failed_connection_tries_next_immediately() {
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
        );
}

#[test]
fn successful_connection_emits_succeeded() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_no_alpn(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt))
        .feed(in_connection_result_positive(v6_attempt), Output::Succeeded);
}

#[test]
fn succeeded_keeps_emitting_succeeded() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_no_alpn(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt))
        .feed(in_connection_result_positive(v6_attempt), Output::Succeeded)
        // After succeeded, continue to emit Succeeded
        .output(Output::Succeeded)
        .output(Output::Succeeded);
}

/// The connection-attempt-delay timer reflects the time *remaining*, not the full delay.
/// Calling process_output partway through the delay should return a timer for the remainder.
#[test]
fn connection_attempt_delay_partial_elapsed() {
    let custom_delay = Duration::from_millis(100);
    let mut s = Scenario::with_config(NetworkConfig {
        connection_attempt_delay: custom_delay,
        ..NetworkConfig::default()
    });
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    // Drive to first connection attempt at time T.
    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_negative(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt));

    // Partway through the delay, the timer reflects only the remainder.
    let elapsed = Duration::from_millis(40);
    s.advance(elapsed).output(Output::Timer {
        duration: custom_delay - elapsed,
    });
}

#[test]
fn cancelled_connection_result_ignored() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (v6_attempt, v4_attempt) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_no_alpn(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h1_h2(v6_attempt))
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        // Start second connection attempt.
        .tick()
        .output(out_attempt_v4_h1_h2(v4_attempt))
        // First connection succeeds, triggering cancellation of the second.
        .feed(
            in_connection_result_positive(v6_attempt),
            Output::CancelConnection { id: v4_attempt },
        )
        .output(Output::Succeeded)
        // User reports an error for the already-cancelled connection.
        // This must not panic.
        .feed(in_connection_result_negative(v4_attempt), Output::Succeeded);
}
