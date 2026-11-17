//! Deliberately vulnerable HTTP API for the DevSecOps PoC.
//!
//! WARNING: this app contains intentional security flaws so that scanners have
//! something to find. Never expose it to a network you don't control.
//! Each planted flaw is tagged with `VULN:`.

use md5::{Digest, Md5};
use regex::Regex;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::process::Command;
use tiny_http::{Header, Response, Server};

/// A handler's result: HTTP status + JSON body.
pub type Reply = (u16, String);

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.replace("%20", " ").replace('+', " ")))
        .collect()
}

pub fn route(method: &str, url: &str) -> Reply {
    let path = url.split('?').next().unwrap_or("/");
    let q = query(url);
    let param = |k: &str| q.get(k).cloned().unwrap_or_default();

    match (method, path) {
        ("GET", "/health") => (200, r#"{"status":"ok"}"#.to_string()),

        ("GET", "/ping") => {
            let host = q.get("host").cloned().unwrap_or_else(|| "127.0.0.1".into());
            // VULN: OS command injection (user input in a shell string). Try ?host=127.0.0.1;id
            match Command::new("sh").arg("-c").arg(format!("ping -c 1 {host}")).output() {
                Ok(out) => (200, format!(r#"{{"output":"{}"}}"#, json_escape(&String::from_utf8_lossy(&out.stdout)))),
                Err(e) => (500, format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string()))),
            }
        }

        ("GET", "/match") => {
            // VULN: user-controlled regex compiled by regex 1.5.4 (CVE-2022-24713, ReDoS)
            match Regex::new(&param("pattern")) {
                Ok(re) => (200, format!(r#"{{"matches":{}}}"#, re.is_match(&param("text")))),
                Err(e) => (400, format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string()))),
            }
        }

        ("GET", "/split") => {
            // Uses smallvec 1.6.0 (CVE-2021-25900)
            let parts: SmallVec<[String; 4]> = param("csv").split(',').map(str::to_string).collect();
            (200, format!(r#"{{"count":{}}}"#, parts.len()))
        }

        ("GET", "/time") => {
            // Uses time 0.1.43 (CVE-2020-26235)
            (200, format!(r#"{{"unix":{}}}"#, time::get_time().sec))
        }

        ("GET", "/hash") => {
            // VULN: weak hash algorithm (MD5)
            let digest = Md5::digest(param("value").as_bytes());
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            (200, format!(r#"{{"md5":"{hex}"}}"#))
        }

        _ => (404, r#"{"error":"not found"}"#.to_string()),
    }
}

fn main() {
    // `poc-rust healthcheck` lets the distroless image (no shell, no curl) run a HEALTHCHECK
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let ok = std::net::TcpStream::connect("127.0.0.1:8080").is_ok();
        std::process::exit(if ok { 0 } else { 1 });
    }

    let server = Server::http("0.0.0.0:8080").expect("bind 0.0.0.0:8080");
    println!("listening on :8080");
    let content_type = Header::from_bytes("Content-Type", "application/json").unwrap();
    for request in server.incoming_requests() {
        let (status, body) = route(request.method().as_str(), request.url());
        let response = Response::from_string(body)
            .with_status_code(status)
            .with_header(content_type.clone());
        let _ = request.respond(response);
    }
}

#[cfg(test)]
mod tests {
    use super::route;

    #[test]
    fn health() {
        assert_eq!(route("GET", "/health"), (200, r#"{"status":"ok"}"#.to_string()));
    }

    #[test]
    fn md5_hash() {
        let (_, body) = route("GET", "/hash?value=abc");
        assert!(body.contains("900150983cd24fb0d6963f7d28e17f72"));
    }

    #[test]
    fn user_regex() {
        assert_eq!(route("GET", "/match?pattern=^a.c$&text=abc").1, r#"{"matches":true}"#);
    }

    #[test]
    fn split_counts() {
        assert_eq!(route("GET", "/split?csv=a,b,c").1, r#"{"count":3}"#);
    }
}
