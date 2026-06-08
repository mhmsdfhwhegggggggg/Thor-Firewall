// Thor Firewall — TLS Inspector & JA3/JA4 Fingerprinting
// فاحص TLS وبصمة JA3/JA4
//
// يستخرج من ClientHello:
//   - JA3 hash  (Salesforce 2017 — معيار الصناعة)
//   - JA4 hash  (FoxIO 2023 — أدق وأحدث)
//   - SNI (Server Name Indication)
//   - ALPN protocols
//   - TLS version
//   - Cipher suites
//   - Extensions list
//
// يُستخدم لـ:
//   - تحديد نوع العميل (Chrome, Firefox, curl, Golang, Python requests)
//   - كشف أدوات الهجوم (Cobalt Strike, Metasploit, custom malware)
//   - تحديد برامج C2 من بصمتها TLS
//
// المرجع:
//   JA3:  https://github.com/salesforce/ja3
//   JA4:  https://github.com/FoxIO-LLC/ja4
//
// SPDX-License-Identifier: MIT

use std::fmt;

use md5::{Digest, Md5};
use tracing::debug;

// ============================================================================
// Constants
// ============================================================================

const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// GREASE values to exclude from JA3 computation
/// https://tools.ietf.org/html/draft-ietf-tls-grease
const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

#[inline]
fn is_grease(val: u16) -> bool {
    GREASE_VALUES.contains(&val)
}

// ============================================================================
// Parsed ClientHello
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct ClientHello {
    pub tls_record_version: u16,
    pub handshake_version:  u16,
    pub cipher_suites:      Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions:         Vec<u16>,
    pub elliptic_curves:    Vec<u16>,   // ext 0x000a
    pub ec_point_formats:   Vec<u8>,    // ext 0x000b
    pub sni:                Option<String>,
    pub alpn:               Vec<String>,
    pub signature_algorithms: Vec<u16>,  // ext 0x000d
    pub supported_versions: Vec<u16>,    // ext 0x002b
}

// ============================================================================
// TLS Fingerprints
// ============================================================================

#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    /// JA3 fingerprint (32-char hex MD5)
    pub ja3:     String,
    /// JA3 string before hashing (for debugging)
    pub ja3_str: String,
    /// JA4 fingerprint (newer standard)
    pub ja4:     String,
    /// Server Name Indication
    pub sni:     Option<String>,
    /// ALPN protocols (h2, http/1.1, etc.)
    pub alpn:    Vec<String>,
    /// Detected TLS version
    pub tls_version: String,
    /// Number of cipher suites
    pub n_ciphers: usize,
}

impl TlsFingerprint {
    /// Whether this fingerprint matches known malware toolkits
    pub fn is_known_malicious(&self) -> bool {
        // Known malicious JA3 hashes (subset — real list has 10,000+)
        const KNOWN_BAD: &[&str] = &[
            "9e10692f1b7f78228b2d4e424db3a98c",  // Metasploit
            "de9f2c7fd25e1b3afad3e85a0226e55e",  // Cobalt Strike default
            "6734f37431670b3ab4292b8f60f29984",  // Hancitor
            "1aa7bf8b9b9db9e8a5a4da41b16c3943",  // Dridex
        ];
        KNOWN_BAD.contains(&self.ja3.as_str())
    }

    /// Whether this is likely an automated/bot client
    pub fn is_automated(&self) -> bool {
        // No ALPN + few cipher suites + common curl/python patterns
        if self.alpn.is_empty() && self.n_ciphers < 5 {
            return true;
        }
        // curl JA3 patterns
        const BOT_JA3: &[&str] = &[
            "51c64c77e60f3980eea90869b68c58a8",  // curl 7.x
            "cbf56e0bcee2e9f55df7f640b14bdc42",  // Python requests
            "b386946a5a44d1ddcc843bc75336dfce",  // Golang net/http
        ];
        BOT_JA3.contains(&self.ja3.as_str())
    }
}

impl fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JA3={} JA4={} SNI={} TLS={}",
            self.ja3,
            self.ja4,
            self.sni.as_deref().unwrap_or("—"),
            self.tls_version,
        )
    }
}

// ============================================================================
// Parser
// ============================================================================

pub struct TlsParser;

impl TlsParser {
    /// Parse raw bytes as a TLS ClientHello.
    /// Returns None if not a valid ClientHello.
    pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
        let mut pos = 0;

        // TLS Record header (5 bytes)
        if data.len() < 5 { return None; }
        if data[pos] != TLS_CONTENT_HANDSHAKE { return None; }
        pos += 1;

        let record_version = u16::from_be_bytes([data[pos], data[pos+1]]);
        pos += 2;

        let record_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;

        if data.len() < pos + record_len { return None; }

        // Handshake header (4 bytes)
        if data[pos] != TLS_HANDSHAKE_CLIENT_HELLO { return None; }
        pos += 1;

        let _handshake_len = ((data[pos] as usize) << 16)
            | ((data[pos+1] as usize) << 8)
            | (data[pos+2] as usize);
        pos += 3;

        if pos + 2 > data.len() { return None; }
        let handshake_version = u16::from_be_bytes([data[pos], data[pos+1]]);
        pos += 2;

        // Random (32 bytes)
        pos += 32;

        // Session ID
        if pos >= data.len() { return None; }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suites
        if pos + 2 > data.len() { return None; }
        let cs_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;
        let mut cipher_suites = Vec::new();
        let cs_end = pos + cs_len;
        while pos + 2 <= cs_end && pos + 2 <= data.len() {
            let cs = u16::from_be_bytes([data[pos], data[pos+1]]);
            if !is_grease(cs) {
                cipher_suites.push(cs);
            }
            pos += 2;
        }
        pos = cs_end;

        // Compression methods
        if pos >= data.len() { return None; }
        let comp_len = data[pos] as usize;
        pos += 1;
        let compression_methods = data[pos..pos+comp_len].to_vec();
        pos += comp_len;

        // Extensions
        if pos + 2 > data.len() { return None; }
        let ext_total_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_total_len;

        let mut extensions       = Vec::new();
        let mut elliptic_curves  = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut sni              = None;
        let mut alpn             = Vec::new();
        let mut signature_algos  = Vec::new();
        let mut supported_versions = Vec::new();

        while pos + 4 <= ext_end && pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos+1]]);
            let ext_len  = u16::from_be_bytes([data[pos+2], data[pos+3]]) as usize;
            pos += 4;

            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }

            let ext_data_end = pos + ext_len;
            if ext_data_end > data.len() { break; }

            match ext_type {
                // SNI (0)
                0x0000 if ext_len > 5 => {
                    let name_len = u16::from_be_bytes([data[pos+3], data[pos+4]]) as usize;
                    if pos + 5 + name_len <= data.len() {
                        if let Ok(name) = std::str::from_utf8(&data[pos+5..pos+5+name_len]) {
                            sni = Some(name.to_string());
                        }
                    }
                }
                // Supported Groups / Elliptic Curves (10)
                0x000a if ext_len >= 2 => {
                    let list_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
                    let mut p = pos + 2;
                    while p + 2 <= pos + 2 + list_len && p + 2 <= data.len() {
                        let curve = u16::from_be_bytes([data[p], data[p+1]]);
                        if !is_grease(curve) { elliptic_curves.push(curve); }
                        p += 2;
                    }
                }
                // EC Point Formats (11)
                0x000b if ext_len >= 1 => {
                    let list_len = data[pos] as usize;
                    ec_point_formats = data[pos+1..pos+1+list_len.min(ext_len-1)].to_vec();
                }
                // ALPN (16)
                0x0010 if ext_len >= 4 => {
                    let mut p = pos + 2;
                    while p + 1 < ext_data_end && p < data.len() {
                        let proto_len = data[p] as usize;
                        p += 1;
                        if p + proto_len <= ext_data_end && p + proto_len <= data.len() {
                            if let Ok(proto) = std::str::from_utf8(&data[p..p+proto_len]) {
                                alpn.push(proto.to_string());
                            }
                        }
                        p += proto_len;
                    }
                }
                // Signature Algorithms (13)
                0x000d if ext_len >= 2 => {
                    let list_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
                    let mut p = pos + 2;
                    while p + 2 <= pos + 2 + list_len && p + 2 <= data.len() {
                        signature_algos.push(u16::from_be_bytes([data[p], data[p+1]]));
                        p += 2;
                    }
                }
                // Supported Versions (43 / 0x002b)
                0x002b if ext_len >= 1 => {
                    let count = data[pos] as usize;
                    let mut p = pos + 1;
                    for _ in 0..count/2 {
                        if p + 2 <= data.len() {
                            let v = u16::from_be_bytes([data[p], data[p+1]]);
                            if !is_grease(v) { supported_versions.push(v); }
                        }
                        p += 2;
                    }
                }
                _ => {}
            }

            pos = ext_data_end;
        }

        Some(ClientHello {
            tls_record_version:  record_version,
            handshake_version:   handshake_version,
            cipher_suites,
            compression_methods,
            extensions,
            elliptic_curves,
            ec_point_formats,
            sni,
            alpn,
            signature_algorithms: signature_algos,
            supported_versions,
        })
    }

    /// Compute JA3 fingerprint from parsed ClientHello
    pub fn ja3(hello: &ClientHello) -> TlsFingerprint {
        // JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        let version  = hello.handshake_version;
        let ciphers  = hello.cipher_suites.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-");
        let exts     = hello.extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");
        let curves   = hello.elliptic_curves.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-");
        let ecpf     = hello.ec_point_formats.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("-");

        let ja3_str  = format!("{},{},{},{},{}", version, ciphers, exts, curves, ecpf);
        let ja3_hash = format!("{:x}", Md5::digest(ja3_str.as_bytes()));

        // Determine TLS version label
        let tls_version = if hello.supported_versions.contains(&0x0304) {
            "TLS 1.3"
        } else if hello.supported_versions.contains(&0x0303) || hello.handshake_version == 0x0303 {
            "TLS 1.2"
        } else if hello.handshake_version == 0x0302 {
            "TLS 1.1"
        } else {
            "TLS 1.0"
        };

        // JA4 (simplified — full spec at https://github.com/FoxIO-LLC/ja4)
        let proto    = if hello.alpn.contains(&"h2".to_string()) { "t" } else { "t" };
        let version4 = match hello.handshake_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            _      => "10",
        };
        let n_ciphers = hello.cipher_suites.len();
        let n_exts    = hello.extensions.len();
        let alpn_code = hello.alpn.first().map(|a| &a[..2.min(a.len())]).unwrap_or("00");
        let ja4 = format!("{}{}{:02}{:02}{}_{}",
            proto, version4, n_ciphers, n_exts, alpn_code,
            &ja3_hash[..12]
        );

        debug!("TLS fingerprint: JA3={} JA4={} SNI={:?}", ja3_hash, ja4, hello.sni);

        TlsFingerprint {
            ja3:        ja3_hash,
            ja3_str,
            ja4,
            sni:        hello.sni.clone(),
            alpn:       hello.alpn.clone(),
            tls_version: tls_version.to_string(),
            n_ciphers,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0035));
        assert!(!is_grease(0x002f));
    }

    #[test]
    fn test_fingerprint_display() {
        let fp = TlsFingerprint {
            ja3: "abc123".to_string(),
            ja3_str: "test".to_string(),
            ja4: "t1312abc123".to_string(),
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
            tls_version: "TLS 1.3".to_string(),
            n_ciphers: 17,
        };
        let s = fp.to_string();
        assert!(s.contains("abc123"));
        assert!(s.contains("example.com"));
    }
}
