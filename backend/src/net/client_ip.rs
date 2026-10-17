//! Resolves the real client IP when running behind cloudflared or a reverse proxy.
//!
//! Forwarding headers are only honoured when the TCP peer is in `trusted_proxies`;
//! otherwise anyone could spoof their address past an IP policy rule.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, request::Parts},
};
use ipnet::IpNet;

use crate::{app::AppState, config::ProxyMode, error::AppError};

#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub mode: ProxyMode,
    pub trusted: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    pub ip: IpAddr,
    /// ISO country code, only from a trusted Cloudflare header.
    pub country: Option<String>,
    pub user_agent: Option<String>,
}

impl ProxySettings {
    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|n| n.contains(&ip))
    }

    pub fn resolve(&self, peer: IpAddr, headers: &HeaderMap) -> ClientInfo {
        let peer = peer.to_canonical();
        let user_agent = header_str(headers, "user-agent").map(|s| s.chars().take(256).collect());
        let mut info = ClientInfo {
            ip: peer,
            country: None,
            user_agent,
        };

        if self.mode == ProxyMode::None {
            return info;
        }
        if !self.is_trusted(peer) {
            if headers.contains_key("cf-connecting-ip") || headers.contains_key("x-forwarded-for") {
                tracing::debug!(%peer, "ignoring forwarding headers from untrusted peer");
            }
            return info;
        }

        match self.mode {
            ProxyMode::None => {}
            ProxyMode::Cloudflare => {
                if let Some(ip) = header_str(headers, "cf-connecting-ip").and_then(|s| s.trim().parse::<IpAddr>().ok()) {
                    info.ip = ip.to_canonical();
                }
                info.country = header_str(headers, "cf-ipcountry")
                    .map(|c| c.trim().to_ascii_uppercase())
                    .filter(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic()) && c != "XX");
            }
            ProxyMode::Forwarded => {
                let hops = forwarded_hops(headers);
                // Walk right-to-left (closest proxy first) and take the first untrusted hop:
                // everything left of it could have been written by the client.
                if let Some(ip) = hops.iter().rev().find(|ip| !self.is_trusted(**ip)).or(hops.first()) {
                    info.ip = *ip;
                }
            }
        }
        info
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Client chain from `X-Forwarded-For`, falling back to RFC 7239 `Forwarded: for=`.
fn forwarded_hops(headers: &HeaderMap) -> Vec<IpAddr> {
    let xff: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .collect();
    if !xff.is_empty() {
        return xff;
    }
    headers
        .get_all("forwarded")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split([',', ';']))
        .filter_map(|part| {
            let (k, v) = part.trim().split_once('=')?;
            if !k.eq_ignore_ascii_case("for") {
                return None;
            }
            parse_forwarded_node(v.trim().trim_matches('"'))
        })
        .collect()
}

/// Parses `1.2.3.4`, `1.2.3.4:80`, `[2001:db8::1]` or `[2001:db8::1]:80`.
fn parse_forwarded_node(s: &str) -> Option<IpAddr> {
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next()?.parse::<IpAddr>().ok().map(|ip| ip.to_canonical());
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    s.parse::<SocketAddr>().ok().map(|sa| sa.ip().to_canonical())
}

impl FromRequestParts<AppState> for ClientInfo {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let ConnectInfo(peer) = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .cloned()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing ConnectInfo")))?;
        Ok(state.proxy.resolve(peer.ip(), &parts.headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn settings(mode: ProxyMode, trusted: &[&str]) -> ProxySettings {
        ProxySettings {
            mode,
            trusted: trusted.iter().map(|s| crate::config::parse_net(s).unwrap()).collect(),
        }
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn mode_none_ignores_headers() {
        let s = settings(ProxyMode::None, &["0.0.0.0/0"]);
        let h = headers(&[("cf-connecting-ip", "9.9.9.9"), ("x-forwarded-for", "8.8.8.8")]);
        assert_eq!(s.resolve(ip("10.0.0.1"), &h).ip, ip("10.0.0.1"));
    }

    #[test]
    fn cloudflare_from_trusted_peer() {
        let s = settings(ProxyMode::Cloudflare, &["172.16.0.0/12"]);
        let h = headers(&[("cf-connecting-ip", "203.0.113.7"), ("cf-ipcountry", "dk")]);
        let info = s.resolve(ip("172.18.0.5"), &h);
        assert_eq!(info.ip, ip("203.0.113.7"));
        assert_eq!(info.country.as_deref(), Some("DK"));
    }

    #[test]
    fn cloudflare_spoof_from_untrusted_peer_ignored() {
        let s = settings(ProxyMode::Cloudflare, &["172.16.0.0/12"]);
        let h = headers(&[("cf-connecting-ip", "203.0.113.7"), ("cf-ipcountry", "DK")]);
        let info = s.resolve(ip("198.51.100.1"), &h);
        assert_eq!(info.ip, ip("198.51.100.1"));
        assert_eq!(info.country, None);
    }

    #[test]
    fn xff_takes_rightmost_untrusted() {
        let s = settings(ProxyMode::Forwarded, &["10.0.0.0/8"]);
        // Client forged "1.1.1.1"; real client 203.0.113.9 was appended by the edge proxy.
        let h = headers(&[("x-forwarded-for", "1.1.1.1, 203.0.113.9, 10.0.0.3")]);
        assert_eq!(s.resolve(ip("10.0.0.2"), &h).ip, ip("203.0.113.9"));
    }

    #[test]
    fn xff_multiple_headers_and_all_trusted() {
        let s = settings(ProxyMode::Forwarded, &["10.0.0.0/8"]);
        let h = headers(&[("x-forwarded-for", "10.1.1.1"), ("x-forwarded-for", "10.2.2.2")]);
        assert_eq!(s.resolve(ip("10.0.0.2"), &h).ip, ip("10.1.1.1"));
    }

    #[test]
    fn forwarded_header_fallback() {
        let s = settings(ProxyMode::Forwarded, &["127.0.0.1"]);
        let h = headers(&[("forwarded", r#"for="[2001:db8::5]:4711";proto=https, for=127.0.0.1"#)]);
        assert_eq!(s.resolve(ip("127.0.0.1"), &h).ip, ip("2001:db8::5"));
    }

    #[test]
    fn ipv4_mapped_peer_is_canonicalised() {
        let s = settings(ProxyMode::Cloudflare, &["127.0.0.1"]);
        let h = headers(&[("cf-connecting-ip", "203.0.113.7")]);
        assert_eq!(s.resolve(ip("::ffff:127.0.0.1"), &h).ip, ip("203.0.113.7"));
    }
}
