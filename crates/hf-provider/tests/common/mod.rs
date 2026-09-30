use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Server {
    pub url: String,
    pub calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn server(status: u16, chunks: Vec<Vec<u8>>) -> Server {
    server_with_type(status, chunks, "application/json").await
}

pub async fn server_with_type(
    status: u16,
    chunks: Vec<Vec<u8>>,
    content_type: &'static str,
) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let len = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|value| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            counter.fetch_add(1, Ordering::SeqCst);
            let header = format!("HTTP/1.1 {status} Fixture\r\nTransfer-Encoding: chunked\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n");
            if socket.write_all(header.as_bytes()).await.is_err() {
                continue;
            }
            for chunk in &chunks {
                let prefix = format!("{:x}\r\n", chunk.len());
                if socket.write_all(prefix.as_bytes()).await.is_err()
                    || socket.write_all(chunk).await.is_err()
                    || socket.write_all(b"\r\n").await.is_err()
                {
                    break;
                }
            }
            // The client deliberately closes early when a response exceeds its budget.
            let _ = socket.write_all(b"0\r\n\r\n").await;
        }
    });
    Server { url, calls, task }
}
