use axum::http::HeaderMap;
use std::net::IpAddr;

/// Extract client IP from request headers (X-Forwarded-For, X-Real-IP) or connection
pub fn extract_client_ip(headers: &HeaderMap, peer_addr: Option<&std::net::SocketAddr>) -> Option<String> {
    // Check X-Forwarded-For (first IP in chain)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip.to_string());
                }
            }
        }
    }

    // Check X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip.to_string());
            }
        }
    }

    // Fallback to peer address
    if let Some(addr) = peer_addr {
        return Some(addr.ip().to_string());
    }

    None
}
