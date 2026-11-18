//! Optimistic QUIC: absent any signal that the origin supports HTTP/3 (no
//! alt-svc, no HTTPS record), a single HTTP/3 attempt races alongside the
//! regular TCP attempts without delaying them.

#![allow(clippy::disallowed_methods, reason = "tests may use Instant::now")]

mod common;
use common::*;

use std::{num::NonZeroU32, time::Instant};

use happy_eyeballs::{
    AltSvc, CONNECTION_ATTEMPT_DELAY, FailureReason, HappyEyeballs, HttpVersion, HttpVersions, Id,
    NetworkConfig, Output,
};

fn optimistic_config() -> NetworkConfig {
    NetworkConfig {
        optimistic_quic: true,
        ..NetworkConfig::default()
    }
}

fn optimistic(output: Output) -> Output {
    let Output::AttemptConnection {
        id,
        endpoint,
        is_ech_retry,
        ..
    } = output
    else {
        panic!("not a connection attempt: {output:?}");
    };
    Output::AttemptConnection {
        id,
        endpoint,
        is_ech_retry,
        optimistic: true,
    }
}

/// Resolve the origin with a negative HTTPS answer and positive AAAA and A
/// answers, leaving the machine right after the first regular attempt (id 3).
fn resolve_without_signal(he: &mut HappyEyeballs, now: Instant) {
    expect_initial_dns_queries(he, now);
    he.input(in_dns_https_negative(Id::from(0)), now);
    he.expect(out_resolution_delay(), now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
    he.expect(out_attempt_v6_h1_h2(Id::from(3)), now);
}

#[test]
fn races_alongside_first_attempt() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(optimistic(out_attempt_v6_h3(Id::from(4))), now);
    he.expect(out_connection_attempt_delay(), now);

    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(out_attempt_v4_h1_h2(Id::from(5)), now);
    he.expect(out_connection_attempt_delay(), now);

    // Only one optimistic attempt is ever made.
    now += CONNECTION_ATTEMPT_DELAY;
    he.expect_idle(now);
}

#[test]
fn success_cancels_tcp() {
    let now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(optimistic(out_attempt_v6_h3(Id::from(4))), now);

    he.input(in_connection_result_positive(Id::from(4)), now);
    he.expect_all(
        [
            Output::CancelConnection { id: Id::from(3) },
            Output::Succeeded,
        ],
        now,
    );
}

#[test]
fn failure_leaves_race_untouched() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(optimistic(out_attempt_v6_h3(Id::from(4))), now);
    he.input(in_connection_result_negative(Id::from(4)), now);
    he.expect(out_connection_attempt_delay(), now);

    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(out_attempt_v4_h1_h2(Id::from(5)), now);
    he.input(in_connection_result_positive(Id::from(3)), now);
    he.expect_all(
        [
            Output::CancelConnection { id: Id::from(5) },
            Output::Succeeded,
        ],
        now,
    );
}

/// The optimistic attempt does not grow the connection attempt delay.
#[test]
fn does_not_grow_delay() {
    let now = Instant::now();
    let config = NetworkConfig {
        connection_attempt_delay_multiplier: NonZeroU32::new(2).unwrap(),
        ..optimistic_config()
    };
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(optimistic(out_attempt_v6_h3(Id::from(4))), now);
    he.expect(out_connection_attempt_delay(), now);
}

/// The whole race fails once the optimistic attempt and every regular attempt
/// have failed.
#[test]
fn all_fail() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(optimistic(out_attempt_v6_h3(Id::from(4))), now);
    he.input(in_connection_result_negative(Id::from(3)), now);
    he.expect(out_attempt_v4_h1_h2(Id::from(5)), now);
    he.input(in_connection_result_negative(Id::from(5)), now);
    // Still waiting on the optimistic attempt.
    now += CONNECTION_ATTEMPT_DELAY;
    he.expect_idle(now);
    he.input(in_connection_result_negative(Id::from(4)), now);
    he.expect(Output::Failed(FailureReason::Connection), now);
}

#[test]
fn disabled_by_default() {
    let now = Instant::now();
    let mut he = HappyEyeballs::new(HOSTNAME, PORT).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(out_connection_attempt_delay(), now);
}

#[test]
fn not_with_https_record() {
    let now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    expect_initial_dns_queries(&mut he, now);
    he.input(in_dns_https_positive_no_alpn(Id::from(0)), now);
    he.expect(out_resolution_delay(), now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
    while let Some(output) = he.process_output(now) {
        if let Output::AttemptConnection { optimistic, .. } = output {
            assert!(!optimistic);
        }
        if matches!(output, Output::Timer { .. }) {
            break;
        }
    }
}

#[test]
fn not_with_alt_svc() {
    let now = Instant::now();
    let config = NetworkConfig {
        alt_svc: vec![AltSvc {
            host: None,
            port: None,
            http_version: HttpVersion::H2,
        }],
        ..optimistic_config()
    };
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();

    expect_initial_dns_queries(&mut he, now);
    he.input(in_dns_https_negative(Id::from(0)), now);
    he.expect(out_resolution_delay(), now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
    he.expect(out_attempt_v6_h1_h2(Id::from(3)), now);
    he.expect(out_connection_attempt_delay(), now);
}

#[test]
fn not_with_h3_disabled() {
    let now = Instant::now();
    let config = NetworkConfig {
        http_versions: HttpVersions {
            h3: false,
            ..HttpVersions::default()
        },
        ..optimistic_config()
    };
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(out_connection_attempt_delay(), now);
}

#[test]
fn not_for_ip_host() {
    let now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config("[2001:db8::1]", PORT, optimistic_config()).unwrap();

    he.expect(out_attempt_v6_h1_h2(Id::from(0)), now);
    he.expect(out_connection_attempt_delay(), now);
}
