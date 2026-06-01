/// Tests for HTTPS/SVCB DNS record handling including ECH, port SvcParams,
/// multiple ServiceInfo records, and SVC1 target name resolution.
mod common;
use common::*;

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use happy_eyeballs::{
    AltSvc, ConnectionAttemptHttpVersions, ConnectionResult, DnsRecordType, DnsResult, EchConfig,
    Endpoint, FailureReason, HttpVersion, Id, Input, IpPreference, NetworkConfig, Output,
    RESOLUTION_DELAY, ServiceInfo,
};

#[test]
fn ech_config_propagated_to_endpoint() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let attempt = s.next_id();

    // HTTPS arrives with an ECH config and a v6 hint while AAAA and A are
    // still in-flight. After the resolution delay the hint is used, and the
    // ECH config must be carried onto the endpoint.
    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                    ipv6_hints: vec![V6_ADDR],
                    ipv4_hints: vec![],
                    ech_config: Some(ech_config()),
                    port: None,
                }])),
            },
            out_resolution_delay(),
        );

    s.advance(RESOLUTION_DELAY)
        .output(Output::AttemptConnection {
            id: attempt,
            endpoint: Endpoint {
                address: SocketAddr::new(V6_ADDR.into(), PORT),
                http_version: ConnectionAttemptHttpVersions::H3,
                ech_config: Some(ech_config()),
            },
            is_ech_retry: false,
        });
}

/// HTTPS RR address hints must be discarded when the corresponding address
/// family returns a negative answer. Per the Happy Eyeballs v3 draft, hints
/// apply only "when A and AAAA records are not available yet"; a negative
/// answer replaces them.
///
/// Tested for both preferences (prefer-V6 with AAAA negative, prefer-V4 with
/// A negative) to verify symmetry.
#[test]
fn hints_discarded_on_negative_answer() {
    struct Case {
        config: NetworkConfig,
        ipv6_hints: Vec<std::net::Ipv6Addr>,
        ipv4_hints: Vec<Ipv4Addr>,
        // Builds inputs/outputs from named ids allocated by the scenario.
        make_first_arrives: fn(Id) -> Input,
        make_second_arrives: fn(Id) -> Input,
        make_attempt_1: fn(Id) -> Output,
        make_attempt_2: fn(Id) -> Output,
        make_attempt_3: fn(Id) -> Output,
        /// Which freshly resolved family is the "first arrives" id.
        first_is_a: bool,
    }

    let cases = vec![
        // Prefer V6: AAAA negative, A positive — V6 hint must be discarded.
        Case {
            config: NetworkConfig::default(),
            ipv6_hints: vec![V6_ADDR],
            ipv4_hints: vec![],
            make_first_arrives: in_dns_a_positive,
            make_second_arrives: in_dns_aaaa_negative,
            make_attempt_1: out_attempt_v4_h3,
            make_attempt_2: out_attempt_v4_h2,
            make_attempt_3: out_attempt_v4_h1_h2,
            first_is_a: true,
        },
        // Prefer V4: A negative, AAAA positive — V4 hint must be discarded.
        Case {
            config: NetworkConfig {
                ip: IpPreference::DualStackPreferV4,
                ..NetworkConfig::default()
            },
            ipv6_hints: vec![],
            ipv4_hints: vec![V4_ADDR],
            make_first_arrives: in_dns_aaaa_positive,
            make_second_arrives: in_dns_a_negative,
            make_attempt_1: out_attempt_v6_h3,
            make_attempt_2: out_attempt_v6_h2,
            make_attempt_3: out_attempt_v6_h1_h2,
            first_is_a: false,
        },
    ];

    for case in cases {
        let mut s = Scenario::with_config(case.config);
        let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
        let (attempt_1, attempt_2, attempt_3) = (s.next_id(), s.next_id(), s.next_id());

        let first_arrives = (case.make_first_arrives)(if case.first_is_a { a } else { aaaa });
        let second_arrives = (case.make_second_arrives)(if case.first_is_a { aaaa } else { a });

        s.output(out_send_dns_https(https))
            .output(out_send_dns_aaaa(aaaa))
            .output(out_send_dns_a(a))
            .feed(first_arrives, out_resolution_delay())
            .feed(second_arrives, out_resolution_delay())
            .feed(
                Input::DnsResult {
                    id: https,
                    result: DnsResult::Https(Ok(vec![ServiceInfo {
                        priority: 1,
                        target_name: HOSTNAME.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                        ipv6_hints: case.ipv6_hints,
                        ipv4_hints: case.ipv4_hints,
                        ech_config: None,
                        port: None,
                    }])),
                },
                (case.make_attempt_1)(attempt_1),
            );

        s.connection_attempts(vec![
            (case.make_attempt_2)(attempt_2),
            (case.make_attempt_3)(attempt_3),
        ]);
    }
}

/// When ECH is disabled in the network config, ECH configs from HTTPS records
/// are ignored: endpoints get `ech_config: None` and the origin fallback is
/// not skipped.
///
/// HTTPS record has ECH + H3 ALPN with v6 hints. AAAA positive for origin.
/// With ECH disabled:
///   - HTTPS bucket uses hints: V6:H3 (no ECH)
///   - Origin fallback is NOT skipped: V6:H2OrH1
///
/// <https://github.com/mozilla/happy-eyeballs/issues/20>
#[test]
fn ech_disabled() {
    let mut s = Scenario::with_config(NetworkConfig {
        ech: false,
        ..NetworkConfig::default()
    });
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_a_negative(a), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_resolution_delay())
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    // Only H3 in ALPN — fallback bucket uses H2OrH1 by default.
                    alpn_http_versions: HashSet::from([HttpVersion::H3]),
                    ipv6_hints: vec![V6_ADDR],
                    ipv4_hints: vec![],
                    ech_config: Some(ech_config()),
                    port: None,
                }])),
            },
            // HTTPS bucket: V6:H3, but ECH stripped.
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H3,
                    ech_config: None,
                },
                is_ech_retry: false,
            },
        );

    // Origin fallback is NOT skipped despite HTTPS record having ECH.
    s.connection_attempts(vec![Output::AttemptConnection {
        id: attempt_2,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2OrH1,
            ech_config: None,
        },
        is_ech_retry: false,
    }]);
}

#[test]
fn ech_config_from_https_applies_to_aaaa() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let attempt = s.next_id();

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: Some(ech_config()),
                    port: None,
                }])),
            },
            out_resolution_delay(),
        )
        .feed(
            in_dns_aaaa_positive(aaaa),
            Output::AttemptConnection {
                id: attempt,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H3,
                    ech_config: Some(ech_config()),
                },
                is_ech_retry: false,
            },
        );
}

#[test]
fn multiple_target_names() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (svc1, attempt) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // HTTPS response with a different target name
        .feed(in_dns_https_positive_svc1(https), out_send_dns_svc1(svc1))
        // Now we have queries for both "example.com" and "svc1.example.com."
        // Getting a positive AAAA for the main host
        .feed(
            in_dns_aaaa_positive(aaaa),
            Output::AttemptConnection {
                id: attempt,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR_2.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H3,
                    ech_config: None,
                },
                is_ech_retry: false,
            },
        );
}

/// Two HTTPS ServiceInfo records where only the first has ECH config ("partial ECH").
/// When any ServiceInfo has ECH, those without ECH are skipped.
/// The origin fallback is also skipped.
///
/// ```dns
/// test.partial_ech.org  HTTPS  1 svc1.example.com. alpn="h3" port=9443 ech="..."
/// test.partial_ech.org  HTTPS  2 svc2.example.com. alpn="h2" port=10443
/// ```
///
/// HOSTNAME resolves AAAA to V6_ADDR and A to V4_ADDR.
/// SVC1 resolves A to V4_ADDR_2. SVC2 DNS is never queried (no ECH).
///
/// Only the ECH-enabled ServiceInfo produces connection attempts:
///
///   priority-1 bucket (SVC1, port 9443, ech): V4_2:H3, V4_2:H2
///   priority-2 bucket (SVC2, port 10443):     skipped (no ECH, not even resolved)
///   fallback   bucket (HOSTNAME):             skipped (no ECH)
#[test]
fn partial_ech_two_service_infos() {
    const SVC2: &str = "svc2.example.com.";
    const SVC1_PORT: u16 = 9443;
    const SVC2_PORT: u16 = 10443;

    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (svc1_aaaa, svc1_a) = (s.next_id(), s.next_id());
    let (attempt_1, attempt_2) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![
                    ServiceInfo {
                        priority: 1,
                        target_name: SVC1.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H3]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: Some(ech_config()),
                        port: Some(SVC1_PORT),
                    },
                    ServiceInfo {
                        priority: 2,
                        target_name: SVC2.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H2]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: None,
                        port: Some(SVC2_PORT),
                    },
                ])),
            },
            // Only SVC1 gets DNS queries — SVC2 is skipped (no ECH)
            Output::SendDnsQuery {
                id: svc1_aaaa,
                hostname: SVC1.into(),
                record_type: DnsRecordType::Aaaa,
            },
        )
        .output(Output::SendDnsQuery {
            id: svc1_a,
            hostname: SVC1.into(),
            record_type: DnsRecordType::A,
        })
        .output(out_resolution_delay())
        // HOSTNAME AAAA positive -> move-on criteria met, but SVC1 has no
        // addresses yet and ECH filtering skips fallback -> no attempt yet.
        .feed(in_dns_aaaa_positive(aaaa), out_resolution_delay())
        .feed(in_dns_a_positive(a), out_resolution_delay())
        // SVC1 AAAA negative
        .feed(in_dns_aaaa_negative(svc1_aaaa), out_resolution_delay())
        // SVC1 A positive -> SVC1 bucket now has addresses, first attempt
        .feed(
            Input::DnsResult {
                id: svc1_a,
                result: DnsResult::A(Ok(vec![V4_ADDR_2])),
            },
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V4_ADDR_2.into(), SVC1_PORT),
                    http_version: ConnectionAttemptHttpVersions::H3,
                    ech_config: Some(ech_config()),
                },
                is_ech_retry: false,
            },
        );

    s.tick().output(Output::AttemptConnection {
        id: attempt_2,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR_2.into(), SVC1_PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: Some(ech_config()),
        },
        is_ech_retry: false,
    });

    s.tick().idle();
}

/// Both ServiceInfo records have ECH. The origin fallback is still skipped
/// because it has no ECH config.
///
/// ```dns
/// example.com  HTTPS  1 svc1.example.com. alpn="h3" port=9443 ech="..."
/// example.com  HTTPS  2 svc2.example.com. alpn="h2" port=10443 ech="..."
/// ```
///
/// HOSTNAME resolves AAAA to V6_ADDR and A to V4_ADDR.
/// SVC1 resolves A to V4_ADDR_2. SVC2 resolves A to V4_ADDR.
///
///   priority-1 bucket (SVC1, port 9443, ech):  V4_2:H3, V4_2:H2
///   priority-2 bucket (SVC2, port 10443, ech): V4:H3, V4:H2
///   fallback   bucket (HOSTNAME):              skipped (no ECH)
#[test]
fn both_service_infos_have_ech_no_origin_fallback() {
    const SVC2: &str = "svc2.example.com.";
    const SVC1_PORT: u16 = 9443;
    const SVC2_PORT: u16 = 10443;

    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (svc1_aaaa, svc1_a, svc2_aaaa, svc2_a) =
        (s.next_id(), s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2, attempt_3, attempt_4) =
        (s.next_id(), s.next_id(), s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![
                    ServiceInfo {
                        priority: 1,
                        target_name: SVC1.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H3]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: Some(ech_config()),
                        port: Some(SVC1_PORT),
                    },
                    ServiceInfo {
                        priority: 2,
                        target_name: SVC2.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H2]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: Some(ech_config()),
                        port: Some(SVC2_PORT),
                    },
                ])),
            },
            // Both SVC1 and SVC2 get DNS queries (both have ECH)
            Output::SendDnsQuery {
                id: svc1_aaaa,
                hostname: SVC1.into(),
                record_type: DnsRecordType::Aaaa,
            },
        )
        .output(Output::SendDnsQuery {
            id: svc1_a,
            hostname: SVC1.into(),
            record_type: DnsRecordType::A,
        })
        .output(Output::SendDnsQuery {
            id: svc2_aaaa,
            hostname: SVC2.into(),
            record_type: DnsRecordType::Aaaa,
        })
        .output(Output::SendDnsQuery {
            id: svc2_a,
            hostname: SVC2.into(),
            record_type: DnsRecordType::A,
        })
        .output(out_resolution_delay())
        // HOSTNAME AAAA/A positive — but fallback will be skipped (no ECH)
        .feed(in_dns_aaaa_positive(aaaa), out_resolution_delay())
        .feed(in_dns_a_positive(a), out_resolution_delay())
        // SVC1 AAAA negative
        .feed(in_dns_aaaa_negative(svc1_aaaa), out_resolution_delay())
        // SVC1 A positive -> first attempt from SVC1 bucket
        .feed(
            Input::DnsResult {
                id: svc1_a,
                result: DnsResult::A(Ok(vec![V4_ADDR_2])),
            },
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V4_ADDR_2.into(), SVC1_PORT),
                    http_version: ConnectionAttemptHttpVersions::H3,
                    ech_config: Some(ech_config()),
                },
                is_ech_retry: false,
            },
        )
        .output(out_connection_attempt_delay())
        // SVC2 AAAA negative
        .feed(
            in_dns_aaaa_negative(svc2_aaaa),
            out_connection_attempt_delay(),
        )
        // SVC2 A positive
        .feed(
            Input::DnsResult {
                id: svc2_a,
                result: DnsResult::A(Ok(vec![V4_ADDR])),
            },
            out_connection_attempt_delay(),
        );

    // Both SVC1 and SVC2 produce attempts (both have ECH).
    // Origin fallback is skipped — no ECH on the origin.
    s.connection_attempts(vec![
        // priority=1 (SVC1, port 9443, ech)
        Output::AttemptConnection {
            id: attempt_2,
            endpoint: Endpoint {
                address: SocketAddr::new(V4_ADDR_2.into(), SVC1_PORT),
                http_version: ConnectionAttemptHttpVersions::H2,
                ech_config: Some(ech_config()),
            },
            is_ech_retry: false,
        },
        // priority=2 (SVC2, port 10443, ech)
        Output::AttemptConnection {
            id: attempt_3,
            endpoint: Endpoint {
                address: SocketAddr::new(V4_ADDR.into(), SVC2_PORT),
                http_version: ConnectionAttemptHttpVersions::H3,
                ech_config: Some(ech_config()),
            },
            is_ech_retry: false,
        },
        Output::AttemptConnection {
            id: attempt_4,
            endpoint: Endpoint {
                address: SocketAddr::new(V4_ADDR.into(), SVC2_PORT),
                http_version: ConnectionAttemptHttpVersions::H2,
                ech_config: Some(ech_config()),
            },
            is_ech_retry: false,
        },
    ]);
}

/// Partial ECH with an alt-svc record on the origin. Both alt-svc and origin
/// fallback are skipped because they carry no ECH config.
///
/// ```dns
/// example.com  HTTPS  1 svc1.example.com. alpn="h3" port=9443 ech="..."
/// example.com  HTTPS  2 svc2.example.com. alpn="h2" port=10443
/// ```
/// Alt-svc: h3 on port 8443
///
/// HOSTNAME resolves AAAA to V6_ADDR and A to V4_ADDR.
/// SVC1 resolves A to V4_ADDR_2.
///
///   priority-1 bucket (SVC1, port 9443, ech): V4_2:H3, V4_2:H2
///   priority-2 bucket (SVC2, port 10443):     skipped (no ECH, not resolved)
///   alt-svc    bucket (port 8443):            skipped (no ECH)
///   fallback   bucket (HOSTNAME, port 443):   skipped (no ECH)
#[test]
fn partial_ech_with_alt_svc() {
    const SVC2: &str = "svc2.example.com.";
    const SVC1_PORT: u16 = 9443;
    const SVC2_PORT: u16 = 10443;
    const ALT_SVC_PORT: u16 = 8443;

    let config = NetworkConfig {
        alt_svc: vec![AltSvc {
            host: None,
            port: Some(ALT_SVC_PORT),
            http_version: HttpVersion::H3,
        }],
        ..NetworkConfig::default()
    };
    let mut s = Scenario::with_config(config);
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (svc1_aaaa, svc1_a) = (s.next_id(), s.next_id());
    let (attempt_1, attempt_2) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![
                    ServiceInfo {
                        priority: 1,
                        target_name: SVC1.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H3]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: Some(ech_config()),
                        port: Some(SVC1_PORT),
                    },
                    ServiceInfo {
                        priority: 2,
                        target_name: SVC2.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H2]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: None,
                        port: Some(SVC2_PORT),
                    },
                ])),
            },
            // Only SVC1 gets DNS queries — SVC2 skipped (no ECH)
            Output::SendDnsQuery {
                id: svc1_aaaa,
                hostname: SVC1.into(),
                record_type: DnsRecordType::Aaaa,
            },
        )
        .output(Output::SendDnsQuery {
            id: svc1_a,
            hostname: SVC1.into(),
            record_type: DnsRecordType::A,
        })
        .output(out_resolution_delay())
        // HOSTNAME AAAA/A positive
        .feed(in_dns_aaaa_positive(aaaa), out_resolution_delay())
        .feed(in_dns_a_positive(a), out_resolution_delay())
        // SVC1 AAAA negative
        .feed(in_dns_aaaa_negative(svc1_aaaa), out_resolution_delay())
        // SVC1 A positive -> first attempt from SVC1 bucket
        .feed(
            Input::DnsResult {
                id: svc1_a,
                result: DnsResult::A(Ok(vec![V4_ADDR_2])),
            },
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V4_ADDR_2.into(), SVC1_PORT),
                    http_version: ConnectionAttemptHttpVersions::H3,
                    ech_config: Some(ech_config()),
                },
                is_ech_retry: false,
            },
        );

    // Only SVC1 (with ECH). Alt-svc, SVC2, and fallback all skipped.
    s.tick().output(Output::AttemptConnection {
        id: attempt_2,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR_2.into(), SVC1_PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: Some(ech_config()),
        },
        is_ech_retry: false,
    });

    s.tick().idle();
}

mod https_port_svcparam_overrides_port_for {
    use super::*;

    fn check(ipv4_hints: Vec<Ipv4Addr>) {
        let mut s = Scenario::new(); // constructed with PORT (443)
        let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
        let attempt = s.next_id();

        // HTTPS arrives with port=8443 while AAAA and A are still in-flight.
        // After the resolution delay the hint is used; the connection attempt
        // must use 8443, not the authority port 443. IPv6 is preferred.
        s.output(out_send_dns_https(https))
            .output(out_send_dns_aaaa(aaaa))
            .output(out_send_dns_a(a))
            .feed(
                Input::DnsResult {
                    id: https,
                    result: DnsResult::Https(Ok(vec![ServiceInfo {
                        priority: 1,
                        target_name: HOSTNAME.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                        ipv6_hints: vec![V6_ADDR],
                        ipv4_hints,
                        ech_config: None,
                        port: Some(CUSTOM_PORT),
                    }])),
                },
                out_resolution_delay(),
            );

        s.advance(RESOLUTION_DELAY)
            .output(out_attempt_v6_h3_custom_port(attempt));
    }

    #[test]
    fn v6_hints() {
        check(vec![]);
    }

    /// HTTPS record with both IPv4 and IPv6 hints and a `port` SvcParam: both
    /// families use the overridden port.
    #[test]
    fn v4_and_v6_hints() {
        check(vec![V4_ADDR]);
    }
}

#[test]
fn https_port_svcparam_applies_to_resolved_a_and_aaaa() {
    let mut s = Scenario::new(); // constructed with PORT (443)
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // HTTPS record with port=8443, no hints
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: None,
                    port: Some(CUSTOM_PORT),
                }])),
            },
            out_resolution_delay(),
        )
        // Positive AAAA: connection attempt must use port 8443, not 443
        .feed(
            in_dns_aaaa_positive(aaaa),
            out_attempt_v6_h3_custom_port(attempt_1),
        )
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        // Positive A: connection attempt must use port 8443, not 443
        .feed(
            in_connection_result_negative(attempt_1),
            out_attempt_v4_h3_custom_port(attempt_2),
        );
}

#[test]
fn https_port_svcparam_applies_but_fallbacks_follow() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let attempt_1 = s.next_id();
    let (attempt_2, attempt_3, attempt_4, attempt_5, attempt_6) = (
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
    );

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // HTTPS record with port=8443, no hints
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: None,
                    port: Some(CUSTOM_PORT),
                }])),
            },
            out_resolution_delay(),
        )
        // Positive AAAA: connection attempt must use port 8443, not 443
        .feed(
            in_dns_aaaa_positive(aaaa),
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), CUSTOM_PORT),
                    http_version: ConnectionAttemptHttpVersions::H3,
                    ech_config: None,
                },
                is_ech_retry: false,
            },
        )
        .feed(in_dns_a_positive(a), out_connection_attempt_delay());

    // Connection attempts using custom port: V4:H3, V6:H2, V4:H2, then
    // fallback on port 443 with default HTTP versions (H2OrH1).
    s.connection_attempts(vec![
        out_attempt_v4_h3_custom_port(attempt_2),
        out_attempt_v6_h2_custom_port(attempt_3),
        out_attempt_v4_h2_custom_port(attempt_4),
        out_attempt_v6_h1_h2(attempt_5),
        out_attempt_v4_h1_h2(attempt_6),
    ]);
}

/// Two HTTPS ServiceInfo records with different priorities and `port` SvcParams.
///
/// ```dns
/// example.com  HTTPS  1 . alpn="h2,h3" port=20007
/// example.com  HTTPS  2 . alpn="h2,h3" port=20008
/// ```
///
/// Connection attempts are grouped by port in priority order, then the
/// authority port as a final fallback:
///
///   priority-1 bucket (port 20007): V6:H3, V4:H3, V6:H2, V4:H2
///   priority-2 bucket (port 20008): V6:H3, V4:H3, V6:H2, V4:H2
///   fallback   bucket (port   443): V6:H3, V4:H3, V6:H2, V4:H2
#[test]
fn https_two_service_infos_with_different_ports() {
    const PORT_1: u16 = 20007;
    const PORT_2: u16 = 20008;
    let mut s = Scenario::new(); // PORT = 443
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (id3, id4, id5, id6) = (s.next_id(), s.next_id(), s.next_id(), s.next_id());
    let (id7, id8, id9, id10) = (s.next_id(), s.next_id(), s.next_id(), s.next_id());
    let (id11, id12) = (s.next_id(), s.next_id());

    let attempt = |id: Id, addr: IpAddr, port: u16, http_version: ConnectionAttemptHttpVersions| {
        Output::AttemptConnection {
            id,
            endpoint: Endpoint {
                address: SocketAddr::new(addr, port),
                http_version,
                ech_config: None,
            },
            is_ech_retry: false,
        }
    };

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // Two ServiceInfo records; the lower priority number wins first.
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![
                    ServiceInfo {
                        priority: 1,
                        target_name: HOSTNAME.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: None,
                        port: Some(PORT_1),
                    },
                    ServiceInfo {
                        priority: 2,
                        target_name: HOSTNAME.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: None,
                        port: Some(PORT_2),
                    },
                ])),
            },
            out_resolution_delay(),
        )
        // AAAA arrives; move-on criteria met. First bucket is PORT_1.
        .feed(
            in_dns_aaaa_positive(aaaa),
            attempt(
                id3,
                V6_ADDR.into(),
                PORT_1,
                ConnectionAttemptHttpVersions::H3,
            ),
        )
        .output(out_connection_attempt_delay())
        .feed(in_dns_a_positive(a), out_connection_attempt_delay());

    s.connection_attempts(vec![
        // Priority-1 bucket (port 20007): V4:H3, V6:H2, V4:H2.
        attempt(
            id4,
            V4_ADDR.into(),
            PORT_1,
            ConnectionAttemptHttpVersions::H3,
        ),
        attempt(
            id5,
            V6_ADDR.into(),
            PORT_1,
            ConnectionAttemptHttpVersions::H2,
        ),
        attempt(
            id6,
            V4_ADDR.into(),
            PORT_1,
            ConnectionAttemptHttpVersions::H2,
        ),
        // Priority-2 bucket (port 20008).
        attempt(
            id7,
            V6_ADDR.into(),
            PORT_2,
            ConnectionAttemptHttpVersions::H3,
        ),
        attempt(
            id8,
            V4_ADDR.into(),
            PORT_2,
            ConnectionAttemptHttpVersions::H3,
        ),
        attempt(
            id9,
            V6_ADDR.into(),
            PORT_2,
            ConnectionAttemptHttpVersions::H2,
        ),
        attempt(
            id10,
            V4_ADDR.into(),
            PORT_2,
            ConnectionAttemptHttpVersions::H2,
        ),
        // Fallback bucket (port 443) uses default HTTP versions.
        out_attempt_v6_h1_h2(id11),
        out_attempt_v4_h1_h2(id12),
    ]);
}

/// Website with HTTPS record with `noDefaultAlpn` set.
///
/// See e.g. <adamwoodland.com>.
#[test]
fn no_default_alpn() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (id3, id4, id5, id6, id7, id8) = (
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
    );

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive(https), out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h3(id3))
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        .feed(in_connection_result_negative(id3), out_attempt_v4_h3(id4))
        .feed(in_connection_result_negative(id4), out_attempt_v6_h2(id5))
        .feed(in_connection_result_negative(id5), out_attempt_v4_h2(id6))
        // Fallback bucket with default HTTP versions (H2OrH1).
        .feed(
            in_connection_result_negative(id6),
            out_attempt_v6_h1_h2(id7),
        )
        .feed(
            in_connection_result_negative(id7),
            out_attempt_v4_h1_h2(id8),
        )
        .feed(
            in_connection_result_negative(id8),
            Output::Failed(FailureReason::Connection),
        );
}

#[test]
fn https_svc1_addresses_trigger_additional_attempts() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (svc1_aaaa, svc1_a) = (s.next_id(), s.next_id());
    let id5 = s.next_id();
    let (id6, id7, id8, id9, id10, id11, id12, id13, id14) = (
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
    );

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![
                    ServiceInfo {
                        priority: 1,
                        target_name: HOSTNAME.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H2, HttpVersion::H3]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: None,
                        port: None,
                    },
                    ServiceInfo {
                        priority: 2,
                        target_name: SVC1.into(),
                        alpn_http_versions: HashSet::from([HttpVersion::H2, HttpVersion::H3]),
                        ipv6_hints: vec![],
                        ipv4_hints: vec![],
                        ech_config: None,
                        port: None,
                    },
                ])),
            },
            Output::SendDnsQuery {
                id: svc1_aaaa,
                hostname: SVC1.into(),
                record_type: DnsRecordType::Aaaa,
            },
        )
        .output(Output::SendDnsQuery {
            id: svc1_a,
            hostname: SVC1.into(),
            record_type: DnsRecordType::A,
        })
        .output(out_resolution_delay())
        .feed(in_dns_aaaa_positive(aaaa), out_attempt_v6_h3(id5))
        .feed(in_dns_a_positive(a), out_connection_attempt_delay())
        .feed(
            Input::DnsResult {
                id: svc1_aaaa,
                result: DnsResult::Aaaa(Ok(vec![V6_ADDR_2])),
            },
            out_connection_attempt_delay(),
        )
        .feed(
            Input::DnsResult {
                id: svc1_a,
                result: DnsResult::A(Ok(vec![V4_ADDR_2])),
            },
            out_connection_attempt_delay(),
        );

    let attempt = |id: Id, addr: IpAddr, http_version: ConnectionAttemptHttpVersions| {
        Output::AttemptConnection {
            id,
            endpoint: Endpoint {
                address: SocketAddr::new(addr, PORT),
                http_version,
                ech_config: None,
            },
            is_ech_retry: false,
        }
    };

    // Addresses respect HTTPS record priority: P1 (HOSTNAME, priority=1) endpoints
    // come before P2 (SVC1, priority=2) endpoints.  V6_ADDR:H3 was already
    // attempted (id=5); the remaining follow in priority order, then fallback.
    s.connection_attempts(vec![
        attempt(id6, V4_ADDR.into(), ConnectionAttemptHttpVersions::H3), // priority=1
        attempt(id7, V6_ADDR.into(), ConnectionAttemptHttpVersions::H2), // priority=1
        attempt(id8, V4_ADDR.into(), ConnectionAttemptHttpVersions::H2), // priority=1
        attempt(id9, V6_ADDR_2.into(), ConnectionAttemptHttpVersions::H3), // priority=2
        attempt(id10, V4_ADDR_2.into(), ConnectionAttemptHttpVersions::H3), // priority=2
        attempt(id11, V6_ADDR_2.into(), ConnectionAttemptHttpVersions::H2), // priority=2
        attempt(id12, V4_ADDR_2.into(), ConnectionAttemptHttpVersions::H2), // priority=2
        // Fallback bucket with default HTTP versions (H2OrH1).
        attempt(id13, V6_ADDR.into(), ConnectionAttemptHttpVersions::H2OrH1),
        attempt(id14, V4_ADDR.into(), ConnectionAttemptHttpVersions::H2OrH1),
    ]);
}

/// HTTPS record port takes precedence over alt-svc port.
///
/// HTTPS record with port=8443 and H3+H2; alt-svc with port=9443 and H3.
/// Expected order:
///   HTTPS bucket    (port 8443): V6:H3, V4:H3, V6:H2, V4:H2
///   alt-svc bucket  (port 9443): V6:H3, V4:H3
///   fallback bucket (port  443): V6:H2OrH1, V4:H2OrH1
#[test]
fn https_port_takes_precedence_over_alt_svc_port() {
    const HTTPS_PORT: u16 = 8443;
    const ALT_SVC_PORT: u16 = 9443;

    let config = NetworkConfig {
        alt_svc: vec![AltSvc {
            host: None,
            port: Some(ALT_SVC_PORT),
            http_version: HttpVersion::H3,
        }],
        ..NetworkConfig::default()
    };
    let mut s = Scenario::with_config(config);
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (id3, id4, id5, id6, id7, id8, id9, id10) = (
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
        s.next_id(),
    );

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // HTTPS record with port=8443
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: None,
                    port: Some(HTTPS_PORT),
                }])),
            },
            out_resolution_delay(),
        )
        // AAAA arrives; HTTPS bucket first (port 8443)
        .feed(
            in_dns_aaaa_positive(aaaa),
            out_attempt(
                id3,
                V6_ADDR.into(),
                HTTPS_PORT,
                ConnectionAttemptHttpVersions::H3,
            ),
        )
        .feed(in_dns_a_positive(a), out_connection_attempt_delay());

    s.connection_attempts(vec![
        // HTTPS bucket (port 8443)
        out_attempt(
            id4,
            V4_ADDR.into(),
            HTTPS_PORT,
            ConnectionAttemptHttpVersions::H3,
        ),
        out_attempt(
            id5,
            V6_ADDR.into(),
            HTTPS_PORT,
            ConnectionAttemptHttpVersions::H2,
        ),
        out_attempt(
            id6,
            V4_ADDR.into(),
            HTTPS_PORT,
            ConnectionAttemptHttpVersions::H2,
        ),
        // Alt-svc bucket (port 9443)
        out_attempt(
            id7,
            V6_ADDR.into(),
            ALT_SVC_PORT,
            ConnectionAttemptHttpVersions::H3,
        ),
        out_attempt(
            id8,
            V4_ADDR.into(),
            ALT_SVC_PORT,
            ConnectionAttemptHttpVersions::H3,
        ),
        // Fallback bucket (port 443) uses default versions only.
        out_attempt(
            id9,
            V6_ADDR.into(),
            PORT,
            ConnectionAttemptHttpVersions::H2OrH1,
        ),
        out_attempt(
            id10,
            V4_ADDR.into(),
            PORT,
            ConnectionAttemptHttpVersions::H2OrH1,
        ),
    ]);
}

/// HTTPS record redirects to a different target name (no IP hints). Addresses
/// resolved for that target name are used in connection attempts, with higher
/// priority than the origin fallback.
///
/// ```dns
/// example.com          HTTPS  1  svc1.example.com.  alpn="h3"
/// svc1.example.com.    AAAA   2001:db8::2
/// svc1.example.com.    A      192.0.2.2
/// example.com          AAAA   2001:db8::1
/// example.com          A      192.0.2.1
/// ```
///
/// Expected connection attempts:
///   SVC1 bucket (priority 1): V6_ADDR_2:H3, V4_ADDR_2:H3
///   fallback bucket (origin): V6:H2OrH1,    V4:H2OrH1
///
/// <https://github.com/mozilla/happy-eyeballs/issues/10>
#[test]
fn target_name_redirect_addresses_used_in_connection_attempts() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (svc1_aaaa, svc1_a) = (s.next_id(), s.next_id());
    let (attempt_1, attempt_2, attempt_3, attempt_4) =
        (s.next_id(), s.next_id(), s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // HTTPS response redirects to SVC1 (different target name, no hints)
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: SVC1.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H3]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: None,
                    port: None,
                }])),
            },
            // Follow-up DNS for the redirected target name
            Output::SendDnsQuery {
                id: svc1_aaaa,
                hostname: SVC1.into(),
                record_type: DnsRecordType::Aaaa,
            },
        )
        .output(Output::SendDnsQuery {
            id: svc1_a,
            hostname: SVC1.into(),
            record_type: DnsRecordType::A,
        })
        .output(out_resolution_delay())
        // SVC1 AAAA positive → move-on criteria met, first attempt uses
        // the redirected target name's resolved address.
        .feed(
            Input::DnsResult {
                id: svc1_aaaa,
                result: DnsResult::Aaaa(Ok(vec![V6_ADDR_2])),
            },
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR_2.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H3,
                    ech_config: None,
                },
                is_ech_retry: false,
            },
        )
        .output(out_connection_attempt_delay())
        // Remaining DNS arrives while first attempt is in progress
        .feed(
            Input::DnsResult {
                id: svc1_a,
                result: DnsResult::A(Ok(vec![V4_ADDR_2])),
            },
            out_connection_attempt_delay(),
        )
        .feed(in_dns_aaaa_positive(aaaa), out_connection_attempt_delay())
        .feed(in_dns_a_positive(a), out_connection_attempt_delay());

    // Remaining attempts: SVC1's V4 address, then origin fallback.
    // SVC1 (priority 1) addresses come before the origin fallback.
    s.connection_attempts(vec![
        // SVC1 bucket (priority 1)
        Output::AttemptConnection {
            id: attempt_2,
            endpoint: Endpoint {
                address: SocketAddr::new(V4_ADDR_2.into(), PORT),
                http_version: ConnectionAttemptHttpVersions::H3,
                ech_config: None,
            },
            is_ech_retry: false,
        },
        // fallback bucket (origin)
        out_attempt_v6_h1_h2(attempt_3),
        out_attempt_v4_h1_h2(attempt_4),
    ]);
}

/// HTTPS record with `alpn="h3"` and `port=8443`. The HTTPS bucket should use
/// H3 at port 8443, but the fallback bucket (origin domain, authority port)
/// must use the default HTTP versions (H2OrH1), not H3 which came from the
/// HTTPS record.
///
/// ```dns
/// example.com  HTTPS  1 . alpn="h3" port=8443
/// example.com  A      192.0.2.1
/// ```
///
/// Expected connection attempts:
///   HTTPS bucket (port 8443): V4:H3
///   fallback bucket (port 443): V4:H2OrH1
#[test]
fn https_fallback_uses_default_http_versions() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2) = (s.next_id(), s.next_id());

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        // HTTPS record with port=8443, alpn=h3 only
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H3]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: None,
                    port: Some(CUSTOM_PORT),
                }])),
            },
            out_resolution_delay(),
        )
        .feed(in_dns_aaaa_negative(aaaa), out_resolution_delay())
        // Positive A: connection attempt uses port 8443 with H3 from HTTPS record
        .feed(
            in_dns_a_positive(a),
            out_attempt_v4_h3_custom_port(attempt_1),
        )
        .output(out_connection_attempt_delay());

    // Fallback on port 443 must use default H2OrH1, NOT H3.
    s.connection_attempts(vec![out_attempt_v4_h1_h2(attempt_2)]);
}

/// When a connection attempt fails with `EchRetry`, the state machine should
/// emit a new connection attempt to the same endpoint with the new ECH config.
///
/// Setup:
///   HTTPS record with ECH config, AAAA positive.
///   First connection attempt uses original ECH config.
///   Server rejects ECH and provides retry_configs.
///   State machine emits a new attempt with updated ECH config.
#[test]
fn ech_retry_same_endpoint() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2) = (s.next_id(), s.next_id());

    let new_ech_config = EchConfig::new(vec![10, 20, 30, 40, 50]);

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H2]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: Some(ech_config()),
                    port: None,
                }])),
            },
            out_resolution_delay(),
        )
        .feed(
            in_dns_aaaa_positive(aaaa),
            // First connection attempt with original ECH config.
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H2,
                    ech_config: Some(ech_config()),
                },
                is_ech_retry: false,
            },
        )
        .output(out_connection_attempt_delay())
        // Server rejects ECH and provides retry_configs.
        .feed(
            Input::ConnectionResult {
                id: attempt_1,
                result: ConnectionResult::EchRetry(new_ech_config.clone()),
            },
            // State machine emits a new attempt with the new ECH config
            // immediately (no delay — this is a server-initiated retry,
            // not a new candidate).
            Output::AttemptConnection {
                id: attempt_2,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H2,
                    ech_config: Some(new_ech_config.clone()),
                },
                is_ech_retry: true,
            },
        );
}

/// `EchRetry` with an empty `EchConfig` models the SSL_ERROR_ECH_RETRY_WITHOUT_ECH
/// path on the consumer side (server told us to retry *without* ECH). The state
/// machine forwards the bytes verbatim, but the retry attempt must still be
/// flagged `is_ech_retry: true` so consumers can label it.
#[test]
fn ech_retry_without_ech_sets_flag() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2) = (s.next_id(), s.next_id());

    let empty_ech_config = EchConfig::new(vec![]);

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H2]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: Some(ech_config()),
                    port: None,
                }])),
            },
            out_resolution_delay(),
        )
        .feed(
            in_dns_aaaa_positive(aaaa),
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H2,
                    ech_config: Some(ech_config()),
                },
                is_ech_retry: false,
            },
        )
        .output(out_connection_attempt_delay())
        .feed(
            Input::ConnectionResult {
                id: attempt_1,
                result: ConnectionResult::EchRetry(empty_ech_config.clone()),
            },
            Output::AttemptConnection {
                id: attempt_2,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H2,
                    ech_config: Some(empty_ech_config.clone()),
                },
                is_ech_retry: true,
            },
        );
}

/// Per RFC 9849 Section 6.1.6:
///
/// > Clients SHOULD NOT accept "retry_config" in response to a connection
/// > initiated in response to a "retry_config".
///
/// The state machine must ignore `EchRetry` on an ECH-retried attempt and
/// treat it as a plain failure, then fall through to remaining endpoints.
#[test]
fn ech_retry_no_infinite_loop() {
    let mut s = Scenario::new();
    let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
    let (attempt_1, attempt_2, attempt_3) = (s.next_id(), s.next_id(), s.next_id());

    let retry_ech_config = EchConfig::new(vec![10, 20, 30, 40, 50]);
    let retry_ech_config_2 = EchConfig::new(vec![60, 70, 80]);

    s.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(
            Input::DnsResult {
                id: https,
                result: DnsResult::Https(Ok(vec![ServiceInfo {
                    priority: 1,
                    target_name: HOSTNAME.into(),
                    alpn_http_versions: HashSet::from([HttpVersion::H2]),
                    ipv6_hints: vec![],
                    ipv4_hints: vec![],
                    ech_config: Some(ech_config()),
                    port: None,
                }])),
            },
            out_resolution_delay(),
        )
        .feed(
            in_dns_aaaa_positive(aaaa),
            Output::AttemptConnection {
                id: attempt_1,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H2,
                    ech_config: Some(ech_config()),
                },
                is_ech_retry: false,
            },
        )
        .output(out_connection_attempt_delay())
        // First EchRetry: accepted, new attempt emitted.
        .feed(
            Input::ConnectionResult {
                id: attempt_1,
                result: ConnectionResult::EchRetry(retry_ech_config.clone()),
            },
            Output::AttemptConnection {
                id: attempt_2,
                endpoint: Endpoint {
                    address: SocketAddr::new(V6_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H2,
                    ech_config: Some(retry_ech_config.clone()),
                },
                is_ech_retry: true,
            },
        )
        .output(out_connection_attempt_delay())
        // Second EchRetry on the retried attempt: ignored, treated as
        // failure. A record still pending, so resolution delay.
        .feed(
            Input::ConnectionResult {
                id: attempt_2,
                result: ConnectionResult::EchRetry(retry_ech_config_2),
            },
            out_resolution_delay(),
        )
        // A record arrives, next endpoint attempted (V4, original ECH
        // from DNS).
        .feed(
            in_dns_a_positive(a),
            Output::AttemptConnection {
                id: attempt_3,
                endpoint: Endpoint {
                    address: SocketAddr::new(V4_ADDR.into(), PORT),
                    http_version: ConnectionAttemptHttpVersions::H2,
                    ech_config: Some(ech_config()),
                },
                is_ech_retry: false,
            },
        );
}
