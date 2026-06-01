mod common;
use common::*;

use std::time::Duration;

use happy_eyeballs::{
    AltSvc, ConnectionAttemptHttpVersions, FailureReason, HappyEyeballs, HttpVersion, HttpVersions,
    NetworkConfig, Output,
};

#[test]
fn ip_host() {
    let mut s = Scenario::with_host("[2001:0DB8::1]");
    let attempt = s.next_id();

    s.output(out_attempt_v6_h1_h2(attempt));
}

#[test]
fn not_url_but_ip() {
    // Neither of these are a valid URL, but they are valid IP addresses.
    HappyEyeballs::new("::1", PORT).unwrap();
    HappyEyeballs::new("127.0.0.1", PORT).unwrap();
}

#[test]
fn alt_svc_construction() {
    let config = NetworkConfig {
        alt_svc: vec![AltSvc {
            host: None,
            port: None,
            http_version: HttpVersion::H3,
        }],
        ..NetworkConfig::default()
    };
    let mut s = Scenario::with_config(config);
    let https = s.next_id();

    // Should still send DNS queries as normal
    s.output(out_send_dns_https(https));
}

#[test]
fn alt_svc_used_immediately() {
    let config = NetworkConfig {
        alt_svc: vec![AltSvc {
            host: None,
            port: None,
            http_version: HttpVersion::H3,
        }],
        ..NetworkConfig::default()
    };
    let mut s = Scenario::with_config(config);
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v6_attempt = s.next_id();

    // Alt-svc with H3 should make H3 available even without HTTPS DNS response
    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_negative(https), out_resolution_delay())
        // Alt-svc provided H3, so we should attempt H3 connection
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h3(v6_attempt));
}

/// Alt-svc with a custom port: connections are attempted at both the alt-svc
/// port and the origin port.
///
/// No HTTPS records in this scenario. Alt-svc says H3 on port 8443.
/// Expected endpoint order:
///   alt-svc bucket  (port 8443): V6:H3, V4:H3
///   fallback bucket (port  443): V6:H2OrH1, V4:H2OrH1
#[test]
fn alt_svc_with_port() {
    let alt_port: u16 = CUSTOM_PORT;
    let config = NetworkConfig {
        alt_svc: vec![AltSvc {
            host: None,
            port: Some(alt_port),
            http_version: HttpVersion::H3,
        }],
        ..NetworkConfig::default()
    };
    let mut s = Scenario::with_config(config);
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_3, attempt_4, attempt_5, attempt_6) =
        (s.next_id(), s.next_id(), s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_negative(https), out_resolution_delay())
        // AAAA arrives, move-on met. First endpoint: alt-svc port V6:H3
        .feed(
            in_dns_aaaa_positive(aaaa),
            out_attempt(
                attempt_3,
                V6_ADDR.into(),
                alt_port,
                ConnectionAttemptHttpVersions::H3,
            ),
        )
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        .connection_attempts(vec![
            // Alt-svc bucket (port 8443): V4:H3
            out_attempt(
                attempt_4,
                V4_ADDR.into(),
                alt_port,
                ConnectionAttemptHttpVersions::H3,
            ),
            // Fallback bucket (port 443): V6:H2OrH1, V4:H2OrH1
            out_attempt(
                attempt_5,
                V6_ADDR.into(),
                PORT,
                ConnectionAttemptHttpVersions::H2OrH1,
            ),
            out_attempt(
                attempt_6,
                V4_ADDR.into(),
                PORT,
                ConnectionAttemptHttpVersions::H2OrH1,
            ),
        ])
        // All connection attempts fail -> should report Failed(Connection)
        .feed_idle(in_connection_result_negative(attempt_3))
        .feed_idle(in_connection_result_negative(attempt_4))
        .feed_idle(in_connection_result_negative(attempt_5))
        .feed(
            in_connection_result_negative(attempt_6),
            Output::Failed(FailureReason::Connection),
        );
}

/// When the host is an IP address and alt-svc specifies a custom port,
/// endpoints should be attempted at both the alt-svc port and the origin port.
///
/// Expected endpoint order:
///   alt-svc bucket  (port 8443): V4_ADDR:H3
///   fallback bucket (port  443): V4_ADDR:H2OrH1
#[test]
fn ip_host_alt_svc_with_port() {
    let config = NetworkConfig {
        alt_svc: vec![AltSvc {
            host: None,
            port: Some(CUSTOM_PORT),
            http_version: HttpVersion::H3,
        }],
        ..NetworkConfig::default()
    };
    let mut s = Scenario::with_host_and_config(&V4_ADDR.to_string(), config);
    let (attempt_0, attempt_1) = (s.next_id(), s.next_id());

    s.output(out_attempt(
        attempt_0,
        V4_ADDR.into(),
        CUSTOM_PORT,
        ConnectionAttemptHttpVersions::H3,
    ))
    .output(out_connection_attempt_delay())
    .connection_attempts(vec![
        // Fallback bucket (port 443): H2OrH1
        out_attempt(
            attempt_1,
            V4_ADDR.into(),
            PORT,
            ConnectionAttemptHttpVersions::H2OrH1,
        ),
    ]);
}

/// Custom resolution and connection attempt delays should be respected by
/// the state machine instead of the default constants.
#[test]
fn custom_delays() {
    let custom_resolution_delay = Duration::from_millis(10);
    let custom_connection_attempt_delay = Duration::from_millis(50);

    let mut s = Scenario::with_config(NetworkConfig {
        resolution_delay: custom_resolution_delay,
        connection_attempt_delay: custom_connection_attempt_delay,
        ..NetworkConfig::default()
    });
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let v4_attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // Should use the custom resolution delay, not the default 50ms.
        .feed(
            in_dns_a_positive(a),
            Output::Timer {
                duration: custom_resolution_delay,
            },
        );

    s.advance(custom_resolution_delay)
        .output(out_attempt_v4_h1_h2(v4_attempt))
        // Should use the custom connection attempt delay, not the default 250ms.
        .output(Output::Timer {
            duration: custom_connection_attempt_delay,
        });
}

/// Config with `version` disabled in `http_versions` and present as the sole alt-svc entry.
fn alt_svc_disabled_config(version: HttpVersion) -> NetworkConfig {
    let http_versions = match version {
        HttpVersion::H3 => HttpVersions {
            h3: false,
            ..Default::default()
        },
        HttpVersion::H2 => HttpVersions {
            h2: false,
            ..Default::default()
        },
        HttpVersion::H1 => HttpVersions {
            h1: false,
            ..Default::default()
        },
    };
    NetworkConfig {
        http_versions,
        alt_svc: vec![AltSvc {
            host: None,
            port: None,
            http_version: version,
        }],
        ..NetworkConfig::default()
    }
}

fn assert_alt_svc_version_disabled(
    version: HttpVersion,
    expected_fallback: ConnectionAttemptHttpVersions,
) {
    let mut s = Scenario::with_host_and_config(&V4_ADDR.to_string(), alt_svc_disabled_config(version));
    let attempt = s.next_id();

    s.output(out_attempt(attempt, V4_ADDR.into(), PORT, expected_fallback));
}

/// Alt-svc H2 entry is filtered out when H2 is disabled in the network config.
#[test]
fn alt_svc_h2_disabled() {
    assert_alt_svc_version_disabled(HttpVersion::H2, ConnectionAttemptHttpVersions::H1);
}

/// Alt-svc H1 entry is filtered out when H1 is disabled in the network config.
#[test]
fn alt_svc_h1_disabled() {
    assert_alt_svc_version_disabled(HttpVersion::H1, ConnectionAttemptHttpVersions::H2);
}
