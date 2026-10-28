//! Shared helpers for the exporter's integration tests.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

/// Answers one GraphQL request: `(query, variables)` to the `data` object.
pub type Handler = Arc<dyn Fn(&str, &Value) -> Value + Send + Sync>;

/// Minimal HTTP server answering the exporter's GraphQL queries from a
/// [`Handler`]; stops when dropped.
pub struct GraphqlServer {
    pub url: String,
    task: JoinHandle<()>,
}

impl Drop for GraphqlServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl GraphqlServer {
    pub async fn start(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0; 8192];
                    let headers_end = loop {
                        let count = stream.read(&mut buffer).await.unwrap();
                        assert!(count > 0);
                        request.extend_from_slice(&buffer[..count]);
                        if let Some(index) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            break index + 4;
                        }
                    };
                    let headers = std::str::from_utf8(&request[..headers_end]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    while request.len() < headers_end + length {
                        let count = stream.read(&mut buffer).await.unwrap();
                        assert!(count > 0);
                        request.extend_from_slice(&buffer[..count]);
                    }
                    let request: Value =
                        serde_json::from_slice(&request[headers_end..headers_end + length])
                            .unwrap();
                    let data = handler(request["query"].as_str().unwrap(), &request["variables"]);
                    let body = serde_json::to_vec(&json!({ "data": data })).unwrap();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(header.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                });
            }
        });
        Self { url, task }
    }
}
