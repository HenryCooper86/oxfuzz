//! A process-local `DefectDojo` stub for publication tests.
//!
//! Binds a loopback listener, answers the import-scan endpoints with a
//! canned success, and records every import's multipart fields so a test can
//! prove *which* owner/target actually reached the integration -- without any
//! real publication. Only the pieces of HTTP the `DefectDojo` client uses
//! are parsed: request headers, `content-length` framing, and the text
//! fields of one `multipart/form-data` body.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long one stub connection may stall before it is dropped. Bounded so a
/// malformed or half-open request cannot hang the accept loop (and the test
/// binary) forever.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// One import request captured by [`DefectDojoStub`].
#[derive(Debug, Clone)]
pub struct CapturedImport {
    /// Request path: `/api/v2/import-scan/` or `/api/v2/reimport-scan/`.
    pub path: String,
    /// Presented `Authorization` header value.
    pub authorization: String,
    /// Decoded `multipart/form-data` text fields (`product_name`,
    /// `test_title`, ...) plus the findings file part under `"file"`.
    pub fields: Vec<(String, String)>,
}

impl CapturedImport {
    /// The decoded value of one captured form field.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// How many findings the import's file part carries.
    ///
    /// # Panics
    /// Panics when the captured import is missing a valid findings document.
    #[must_use]
    pub fn findings_count(&self) -> usize {
        let document: serde_json::Value =
            serde_json::from_str(self.field("file").expect("import has a findings file"))
                .expect("findings document is valid JSON");
        document
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .expect("findings document contains an array")
            .len()
    }
}

/// A process-local HTTP stub answering `DefectDojo`'s import endpoints.
///
/// One background thread accepts connections sequentially and answers each
/// with the canned import success `{"test": 7, "engagement": 3}`, recording
/// the request. Tests read what arrived through [`Self::imports_for`].
pub struct DefectDojoStub {
    url: String,
    imports: Arc<Mutex<Vec<CapturedImport>>>,
}

impl DefectDojoStub {
    /// Bind and start the stub on an ephemeral loopback port.
    ///
    /// # Panics
    /// Panics if a loopback listener cannot be bound or its address read.
    #[must_use]
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback stub listener");
        let url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("bound listener has a local address")
        );
        let imports: Arc<Mutex<Vec<CapturedImport>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&imports);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                // Serve inline: no per-request threads to leak, and the IO
                // timeout bounds how long one bad connection can stall the
                // loop. A dropped request is skipped; the capture assertions
                // decide what should have arrived.
                let Ok(mut stream) = stream else {
                    continue;
                };
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .expect("set stub read timeout");
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .expect("set stub write timeout");
                if let Err(error) = serve_import(&mut stream, &recorder) {
                    eprintln!("stub DefectDojo request dropped: {error}");
                }
            }
        });
        Self { url, imports }
    }

    /// The stub's base URL (what a `defectdojo.toml` `url` should point at).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Imports captured for `product_name`, the requesting test's unique
    /// project name, so parallel tests can read only their own requests.
    #[must_use]
    pub fn imports_for(&self, product: &str) -> Vec<CapturedImport> {
        // A poisoned lock only happens if the capture writer panicked
        // mid-push; the records it protected are still readable.
        self.imports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|captured| captured.field("product_name") == Some(product))
            .cloned()
            .collect()
    }
}

/// Serve exactly one HTTP request: capture the import, answer like
/// `DefectDojo`'s import-scan endpoint, close.
fn serve_import(
    stream: &mut TcpStream,
    imports: &Arc<Mutex<Vec<CapturedImport>>>,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(at) = find_subslice(&buffer, b"\r\n\r\n") {
            break at + 4;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request headers truncated",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    // External-HTTP-boundary parsing: absent or malformed framing values
    // degrade to "no body" rather than failing the capture; the field
    // assertions then report what actually arrived.
    let content_length = header_value(&headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = buffer[header_end..].to_vec();

    imports.lock().unwrap().push(CapturedImport {
        path: headers
            .lines()
            .next()
            .and_then(|request| request.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_owned(),
        authorization: header_value(&headers, "authorization").unwrap_or_default(),
        fields: parse_multipart_fields(
            &header_value(&headers, "content-type").unwrap_or_default(),
            &body,
        ),
    });

    let payload = br#"{"test": 7, "engagement": 3}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

/// The trimmed value of `headers`'s `name` header, if present.
fn header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        line.split_once(':').and_then(|(key, value)| {
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Decode the text fields (and the findings file part) of one
/// `multipart/form-data` body. Stub-grade parsing: the field values the
/// assertions read are short ASCII produced by the `DefectDojo` client.
fn parse_multipart_fields(content_type: &str, body: &[u8]) -> Vec<(String, String)> {
    let Some(boundary) = content_type.split("boundary=").nth(1) else {
        return Vec::new();
    };
    let boundary = boundary.trim().trim_matches('"');
    let separator = format!("--{boundary}").into_bytes();
    let mut fields = Vec::new();
    let mut start = 0;
    while let Some(at) = find_subslice(&body[start..], &separator) {
        let part_begin = start + at + separator.len();
        // A part ends at the next boundary separator.
        let Some(next) = find_subslice(&body[part_begin..], &separator) else {
            break;
        };
        let part = &body[part_begin..part_begin + next];
        if let Some(name_at) = find_subslice(part, b"name=\"") {
            let name_begin = name_at + 6;
            let Some(name_end) = find_subslice(&part[name_begin..], b"\"") else {
                start = part_begin + next;
                continue;
            };
            let name =
                String::from_utf8_lossy(&part[name_begin..name_begin + name_end]).to_string();
            if let Some(value_at) = find_subslice(part, b"\r\n\r\n") {
                let mut value_end = part.len();
                if part.ends_with(b"\r\n") {
                    value_end -= 2;
                }
                let value =
                    String::from_utf8_lossy(&part[value_at + 4..value_end.max(value_at + 4)])
                        .to_string();
                fields.push((name, value));
            }
        }
        start = part_begin + next;
    }
    fields
}
