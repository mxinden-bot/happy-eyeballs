mod common;
use common::*;

use happy_eyeballs::{
    ConnectionResult, EchConfig, HttpVersion, Id, Input, ServiceInfo, TargetName,
};

#[test]
fn id_roundtrip() {
    for n in [0u64, 42] {
        assert_eq!(u64::from(Id::from(n)), n);
    }
}

#[test]
fn ech_config_as_ref() {
    assert_eq!(ech_config().as_ref(), ECH_CONFIG_BYTES);
}

#[test]
fn target_name_conversions() {
    let name = TargetName::from(HOSTNAME);
    assert_eq!(format!("{name:?}"), HOSTNAME);
    assert_eq!(String::from(name), HOSTNAME);
}

#[test]
fn service_info_debug() {
    // With optional fields populated: all conditional fields must appear.
    let full = ServiceInfo {
        priority: 1,
        target_name: HOSTNAME.into(),
        alpn_http_versions: [HttpVersion::H3].into(),
        ech_config: Some(ech_config()),
        ipv4_hints: vec![V4_ADDR],
        ipv6_hints: vec![V6_ADDR],
        port: None,
    };
    let s = format!("{full:?}");
    assert!(s.contains("alpn"), "missing 'alpn': {s}");
    assert!(s.contains("ipv4"), "missing 'ipv4': {s}");
    assert!(s.contains("ipv6"), "missing 'ipv6': {s}");

    // With optional fields empty: conditional fields must not appear.
    let bare = ServiceInfo {
        alpn_http_versions: Default::default(),
        ech_config: None,
        ipv4_hints: vec![],
        ipv6_hints: vec![],
        ..full
    };
    let s = format!("{bare:?}");
    assert!(!s.contains("alpn"), "unexpected 'alpn': {s}");
    assert!(!s.contains("ipv4"), "unexpected 'ipv4': {s}");
    assert!(!s.contains("ipv6"), "unexpected 'ipv6': {s}");
}

#[test]
fn happy_eyeballs_debug() {
    let mut s = Scenario::new();

    // Fresh domain host: always has "target" and "port", never "dns_queries" yet.
    let dbg = format!("{:?}", s.he());
    assert!(dbg.contains("target"), "missing 'target': {dbg}");
    assert!(dbg.contains("port"), "missing 'port': {dbg}");
    assert!(
        !dbg.contains("dns_queries"),
        "unexpected 'dns_queries': {dbg}"
    );

    // After first process_output, dns_queries is populated.
    let _ = s.process();
    let dbg = format!("{:?}", s.he());
    assert!(dbg.contains("dns_queries"), "missing 'dns_queries': {dbg}");

    // Set up a hostname-based HE with an HTTPS record that provides ECH
    // config, so the connection attempt carries ECH and EchRetry is valid.
    let mut s2 = Scenario::new();
    let (https, aaaa, a) = (s2.next_id(), s2.next_id(), s2.next_id());
    let attempt = s2.next_id();

    // Drive through DNS queries and feed the HTTPS+ECH record.
    s2.output(out_send_dns_https(https))
        .output(out_send_dns_aaaa(aaaa))
        .output(out_send_dns_a(a))
        .feed(in_dns_https_positive_ech(https), out_resolution_delay());

    // AAAA arrives; a connection attempt carrying ECH config is emitted.
    let now = s2.now();
    s2.he().process_input(in_dns_aaaa_positive(aaaa), now);
    let _ = s2.process();
    let dbg = format!("{:?}", s2.he());
    assert!(
        dbg.contains("connection_attempts"),
        "missing 'connection_attempts': {dbg}"
    );

    // Feed EchRetry for the in-progress connection to populate ech_retries.
    s2.he().process_input(
        Input::ConnectionResult {
            id: attempt,
            result: ConnectionResult::EchRetry(EchConfig::new(vec![10, 20, 30])),
        },
        now,
    );
    let dbg = format!("{:?}", s2.he());
    assert!(dbg.contains("ech_retries"), "missing 'ech_retries': {dbg}");
}
