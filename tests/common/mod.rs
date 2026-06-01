#![allow(dead_code)]

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use happy_eyeballs::{
    CONNECTION_ATTEMPT_DELAY, ConnectionAttemptHttpVersions, ConnectionResult, DnsRecordType,
    DnsResult, EchConfig, Endpoint, HappyEyeballs, HttpVersion, Id, Input, NetworkConfig, Output,
    RESOLUTION_DELAY, ServiceInfo,
};

pub const HOSTNAME: &str = "example.com";
pub const SVC1: &str = "svc1.example.com.";
pub const PORT: u16 = 443;
pub const CUSTOM_PORT: u16 = 8443;
pub const V6_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
pub const V6_ADDR_2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
pub const V6_ADDR_3: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);
pub const V4_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub const V4_ADDR_2: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
pub const ECH_CONFIG_BYTES: &[u8] = &[1, 2, 3, 4, 5];

pub fn ech_config() -> EchConfig {
    EchConfig::new(ECH_CONFIG_BYTES.to_vec())
}

/// Sequential [`Id`] allocator for tests.
///
/// The state machine hands out ids from a simple incrementing counter (DNS
/// queries first, then connection attempts). Mirroring that here lets a test
/// bind ids to meaningful names — `let aaaa = ids.next_id();` — instead of
/// hard-coding `Id::from(0)`, `Id::from(1)`, ...
#[derive(Debug, Default)]
pub struct IdSeq(u64);

impl IdSeq {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the next sequential id (`0`, `1`, `2`, ...).
    pub fn next_id(&mut self) -> Id {
        let id = Id::from(self.0);
        self.0 += 1;
        id
    }
}

/// Fluent test driver for a [`HappyEyeballs`] state machine.
///
/// Owns the machine, the current time, and a sequential [`IdSeq`], so a test
/// reads as a transcript of expected outputs and fed inputs rather than a
/// `Vec<(Option<Input>, Option<Output>)>` with hand-numbered ids and a
/// manually threaded `now`.
///
/// ```ignore
/// let mut s = Scenario::new();
/// let (https, aaaa, a) = (s.next_id(), s.next_id(), s.next_id());
/// s.output(out_send_dns_https(https))
///     .output(out_send_dns_aaaa(aaaa))
///     .output(out_send_dns_a(a))
///     .feed(in_dns_https_negative(https), out_resolution_delay());
/// ```
pub struct Scenario {
    he: HappyEyeballs,
    now: Instant,
    ids: IdSeq,
}

impl Scenario {
    /// Default-config scenario for [`HOSTNAME`]:[`PORT`].
    pub fn new() -> Self {
        let (now, he) = setup();
        Self::from_parts(now, he)
    }

    /// Scenario with a custom [`NetworkConfig`].
    pub fn with_config(config: NetworkConfig) -> Self {
        let (now, he) = setup_with_config(config);
        Self::from_parts(now, he)
    }

    /// Scenario for a custom host (e.g. an IP literal) on [`PORT`].
    pub fn with_host(host: &str) -> Self {
        let _ = env_logger::builder().is_test(true).try_init();
        let he = HappyEyeballs::new(host, PORT).unwrap();
        Self::from_parts(Instant::now(), he)
    }

    /// Scenario for a custom host and [`NetworkConfig`] on [`PORT`].
    pub fn with_host_and_config(host: &str, config: NetworkConfig) -> Self {
        let _ = env_logger::builder().is_test(true).try_init();
        let he = HappyEyeballs::new_with_network_config(host, PORT, config).unwrap();
        Self::from_parts(Instant::now(), he)
    }

    fn from_parts(now: Instant, he: HappyEyeballs) -> Self {
        Self {
            he,
            now,
            ids: IdSeq::new(),
        }
    }

    /// Allocates the next sequential [`Id`] (see [`IdSeq`]).
    pub fn next_id(&mut self) -> Id {
        self.ids.next_id()
    }

    /// Advances time by one [`CONNECTION_ATTEMPT_DELAY`].
    pub fn tick(&mut self) -> &mut Self {
        self.advance(CONNECTION_ATTEMPT_DELAY)
    }

    /// Advances time by `delay`.
    pub fn advance(&mut self, delay: Duration) -> &mut Self {
        self.now += delay;
        self
    }

    /// Asserts the next output is `expected`.
    pub fn output(&mut self, expected: Output) -> &mut Self {
        assert_eq!(Some(expected), self.he.process_output(self.now));
        self
    }

    /// Asserts there is no further output at the current time.
    pub fn idle(&mut self) -> &mut Self {
        assert_eq!(None, self.he.process_output(self.now));
        self
    }

    /// Feeds `input`, then asserts the next output is `expected`.
    pub fn feed(&mut self, input: Input, expected: Output) -> &mut Self {
        self.he.process_input(input, self.now);
        self.output(expected)
    }

    /// Feeds `input` and asserts it produces no output.
    pub fn feed_idle(&mut self, input: Input) -> &mut Self {
        self.he.process_input(input, self.now);
        self.idle()
    }

    /// Drives the connection-attempt race: for each expected `attempt`,
    /// advances one [`CONNECTION_ATTEMPT_DELAY`], asserts the attempt is
    /// emitted, then asserts the next attempt-delay timer. After the last
    /// attempt, advances once more and asserts the race is quiescent.
    pub fn connection_attempts(&mut self, attempts: Vec<Output>) -> &mut Self {
        for attempt in attempts {
            self.tick()
                .output(attempt)
                .output(out_connection_attempt_delay());
        }
        self.tick().idle()
    }

    /// Processes one output at the current time without any assertion, for
    /// the rare test that inspects the emitted value directly.
    pub fn process(&mut self) -> Option<Output> {
        self.he.process_output(self.now)
    }

    /// Current time, for the rare case a test needs it directly.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Borrows the underlying machine for cases the builder does not cover
    /// (e.g. driving a manual `process_output` loop).
    pub fn he(&mut self) -> &mut HappyEyeballs {
        &mut self.he
    }
}

impl Default for Scenario {
    fn default() -> Self {
        Self::new()
    }
}

pub trait HappyEyeballsExt {
    fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant);
    fn expect_connection_attempts(&mut self, now: &mut Instant, connections: Vec<Output>);
}

impl HappyEyeballsExt for HappyEyeballs {
    fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant) {
        for (input, expected_output) in input_output {
            if let Some(input) = input {
                self.process_input(input, now);
            }
            let output = self.process_output(now);
            assert_eq!(expected_output, output);
        }
    }

    fn expect_connection_attempts(&mut self, now: &mut Instant, connections: Vec<Output>) {
        for conn in connections {
            *now += CONNECTION_ATTEMPT_DELAY;
            self.expect(
                vec![
                    (None, Some(conn)),
                    (None, Some(out_connection_attempt_delay())),
                ],
                *now,
            );
        }
        *now += CONNECTION_ATTEMPT_DELAY;
        self.expect(vec![(None, None)], *now);
    }
}

pub fn in_dns_https_positive(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: None,
            port: None,
        }])),
    }
}

pub fn in_dns_https_positive_ech(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: Some(ech_config()),
            port: None,
        }])),
    }
}

pub fn in_dns_https_positive_no_alpn(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::new(),
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: None,
            port: None,
        }])),
    }
}

fn in_dns_https_with_hints(id: Id, ipv4_hints: Vec<Ipv4Addr>, ipv6_hints: Vec<Ipv6Addr>) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv4_hints,
            ipv6_hints,
            ech_config: None,
            port: None,
        }])),
    }
}

pub fn in_dns_https_positive_v6_hints(id: Id) -> Input {
    in_dns_https_with_hints(id, vec![], vec![V6_ADDR])
}

pub fn in_dns_https_positive_v4_hints(id: Id) -> Input {
    in_dns_https_with_hints(id, vec![V4_ADDR], vec![])
}

pub fn in_dns_https_positive_v4_and_v6_hints(id: Id) -> Input {
    in_dns_https_with_hints(id, vec![V4_ADDR], vec![V6_ADDR])
}

pub fn in_dns_https_positive_svc1(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: SVC1.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints: vec![V6_ADDR_2],
            ipv4_hints: vec![],
            ech_config: None,
            port: None,
        }])),
    }
}

pub fn in_dns_https_negative(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Err(())),
    }
}

pub fn in_dns_aaaa_positive(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Aaaa(Ok(vec![V6_ADDR])),
    }
}

pub fn in_dns_a_positive(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::A(Ok(vec![V4_ADDR])),
    }
}

pub fn in_dns_aaaa_negative(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Aaaa(Err(())),
    }
}

pub fn in_dns_a_negative(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::A(Err(())),
    }
}

pub fn in_connection_result_positive(id: Id) -> Input {
    Input::ConnectionResult {
        id,
        result: ConnectionResult::Success,
    }
}

pub fn in_connection_result_negative(id: Id) -> Input {
    Input::ConnectionResult {
        id,
        result: ConnectionResult::Failure("connection refused".to_string()),
    }
}

pub fn in_connection_result_ech_retry(id: Id) -> Input {
    Input::ConnectionResult {
        id,
        result: ConnectionResult::EchRetry(ech_config()),
    }
}

pub fn out_send_dns_https(id: Id) -> Output {
    Output::SendDnsQuery {
        id,
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::Https,
    }
}

pub fn out_send_dns_aaaa(id: Id) -> Output {
    Output::SendDnsQuery {
        id,
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::Aaaa,
    }
}

pub fn out_send_dns_svc1(id: Id) -> Output {
    Output::SendDnsQuery {
        id,
        hostname: SVC1.into(),
        record_type: DnsRecordType::Aaaa,
    }
}

pub fn out_send_dns_a(id: Id) -> Output {
    Output::SendDnsQuery {
        id,
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::A,
    }
}

pub fn out_attempt_v6_h1_h2(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2OrH1,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v6_h2(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v6_h3(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v6_h3_custom_port(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), CUSTOM_PORT),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v4_h1_h2(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2OrH1,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v4_h2(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v4_h3(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v4_h3_custom_port(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), CUSTOM_PORT),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v6_h2_custom_port(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), CUSTOM_PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt_v4_h2_custom_port(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), CUSTOM_PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_attempt(
    id: Id,
    addr: IpAddr,
    port: u16,
    http_version: ConnectionAttemptHttpVersions,
) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(addr, port),
            http_version,
            ech_config: None,
        },
        is_ech_retry: false,
    }
}

pub fn out_resolution_delay() -> Output {
    Output::Timer {
        duration: RESOLUTION_DELAY,
    }
}

pub fn out_connection_attempt_delay() -> Output {
    Output::Timer {
        duration: CONNECTION_ATTEMPT_DELAY,
    }
}

pub fn setup() -> (Instant, HappyEyeballs) {
    setup_with_config(NetworkConfig::default())
}

pub fn setup_with_config(config: NetworkConfig) -> (Instant, HappyEyeballs) {
    let _ = env_logger::builder().is_test(true).try_init();
    let now = Instant::now();
    let he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();
    (now, he)
}
