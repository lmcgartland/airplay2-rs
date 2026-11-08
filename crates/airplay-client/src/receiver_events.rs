//! The events channel: requests the *receiver* sends to us.
//!
//! In SETUP phase 1 the receiver names an `eventPort`, and the sender opens a
//! TCP connection to it. After pair-verify this connection is encrypted
//! (HomeKit framing, keys derived from the pair-verify shared secret with the
//! `Events-*` labels), and the receiver uses it to send RTSP-formatted
//! requests such as remote-control commands (e.g. the user pausing or
//! scrubbing on the Apple TV remote). Each request must be answered, so the
//! channel is serviced by its own task that replies and forwards what it
//! received over an unbounded channel.

use std::collections::HashMap;

use airplay_crypto::chacha::ControlCipher;
use airplay_crypto::keys::{SessionKeys, SharedSecret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// A request the receiver sent on the events channel.
#[derive(Debug, Clone)]
pub struct ReceiverRequest {
    pub method: String,
    pub uri: String,
    /// Header names are lower-cased.
    pub headers: HashMap<String, String>,
    /// Usually a binary plist.
    pub body: Vec<u8>,
}

impl ReceiverRequest {
    /// The body decoded as a plist, if it is one.
    pub fn body_plist(&self) -> Option<plist::Value> {
        if self.body.is_empty() {
            return None;
        }
        plist::Value::from_reader(std::io::Cursor::new(&self.body)).ok()
    }
}

/// A remote-control command issued on the receiver itself (e.g. with the Apple
/// TV remote) and sent to us as `POST /command` with `type =
/// sendMediaRemoteCommand`. The sender is expected to act on it.
#[derive(Debug, Clone, PartialEq)]
pub enum RemoteCommand {
    /// `play`
    Play,
    /// `paus`
    Pause,
    /// `nitm` (next item)
    NextItem,
    /// `spos`: seek to an absolute position, in seconds
    /// (`kMRMediaRemoteOptionPlaybackPosition`).
    SetPosition(f64),
    /// Any other command, by its four-letter code (e.g. a previous-item request).
    Other(String),
}

impl ReceiverRequest {
    /// The remote-control command in this request, if it is one.
    pub fn remote_command(&self) -> Option<RemoteCommand> {
        if self.method != "POST" || self.uri != "/command" {
            return None;
        }
        let plist = self.body_plist()?;
        let dict = plist.as_dictionary()?;
        if dict.get("type")?.as_string()? != "sendMediaRemoteCommand" {
            return None;
        }
        let params = dict.get("params").and_then(|p| p.as_dictionary());
        Some(match dict.get("value")?.as_string()? {
            "play" => RemoteCommand::Play,
            "paus" => RemoteCommand::Pause,
            "nitm" => RemoteCommand::NextItem,
            "spos" => {
                let position = params?.get("kMRMediaRemoteOptionPlaybackPosition")?;
                RemoteCommand::SetPosition(
                    position.as_real().or_else(|| position.as_signed_integer().map(|i| i as f64))?,
                )
            }
            other => RemoteCommand::Other(other.to_string()),
        })
    }
}

/// Something that happened on the events channel.
#[derive(Debug, Clone)]
pub enum ReceiverEvent {
    /// The receiver sent a request (already answered with `200 OK`).
    Request(ReceiverRequest),
    /// The channel closed (receiver went away or sent undecryptable data).
    Closed,
}

/// Start servicing `stream`. Returns the receiving end of the event channel.
pub(crate) fn spawn(stream: TcpStream, shared_secret: [u8; 32]) -> mpsc::UnboundedReceiver<ReceiverEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run(stream, shared_secret, &tx).await {
            debug!("Events channel ended: {}", e);
        }
        let _ = tx.send(ReceiverEvent::Closed);
    });
    rx
}

async fn run(
    mut stream: TcpStream,
    shared_secret: [u8; 32],
    tx: &mpsc::UnboundedSender<ReceiverEvent>,
) -> Result<(), String> {
    let keys = SessionKeys::derive_events_keys(&SharedSecret::new(shared_secret.to_vec()))
        .map_err(|e| e.to_string())?;
    let write = *keys.write_key.as_bytes();
    let read = *keys.read_key.as_bytes();

    // The labels don't say which side writes with which key; whichever
    // assignment authenticates the first frame is the right one. (A failed
    // decrypt doesn't advance a cipher's counter.)
    let mut candidates = vec![
        ControlCipher::new(read, write),  // we write with Read, receiver writes with Write
        ControlCipher::new(write, read),
    ];
    let mut cipher: Option<ControlCipher> = None;
    let mut pending: Vec<u8> = Vec::new();

    loop {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
        let len = u16::from_le_bytes(len_buf);
        let mut block = vec![0u8; len as usize + 16];
        stream.read_exact(&mut block).await.map_err(|e| e.to_string())?;

        let plain = match cipher.as_mut() {
            Some(c) => c.decrypt_block(&block, len).map_err(|e| e.to_string())?,
            None => {
                let mut found = None;
                for (i, c) in candidates.iter_mut().enumerate() {
                    if let Ok(p) = c.decrypt_block(&block, len) {
                        found = Some((i, p));
                        break;
                    }
                }
                let (i, p) = found.ok_or("first events frame did not authenticate with either key assignment")?;
                info!("Events channel: key assignment #{} authenticated", i);
                cipher = Some(candidates.swap_remove(i));
                p
            }
        };
        pending.extend_from_slice(&plain);

        while let Some(msg) = take_message(&mut pending) {
            match msg {
                Message::Request(req) => {
                    info!(
                        "Events channel request: {} {} (headers: {:?}, {} body bytes)",
                        req.method, req.uri, req.headers, req.body.len()
                    );
                    if let Some(p) = req.body_plist() {
                        info!("Events channel body: {:?}", p);
                    }
                    let cseq = req.headers.get("cseq").cloned().unwrap_or_else(|| "0".into());
                    let reply = format!("RTSP/1.0 200 OK\r\nServer: AirTunes/366.0\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n", cseq);
                    let framed = cipher
                        .as_mut()
                        .expect("cipher is set once a frame decrypted")
                        .encrypt(reply.as_bytes())
                        .map_err(|e| e.to_string())?;
                    stream.write_all(&framed).await.map_err(|e| e.to_string())?;
                    if tx.send(ReceiverEvent::Request(req)).is_err() {
                        return Ok(()); // nobody is listening any more
                    }
                }
                Message::Response => debug!("Events channel: ignoring a response"),
            }
        }
    }
}

enum Message {
    Request(ReceiverRequest),
    Response,
}

/// Remove one complete RTSP-style message from the front of `buf`, if there is one.
fn take_message(buf: &mut Vec<u8>) -> Option<Message> {
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let start = lines.next()?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let content_length = headers.get("content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    let total = header_end + 4 + content_length;
    if buf.len() < total {
        return None; // body still arriving
    }
    let body = buf[header_end + 4..total].to_vec();
    buf.drain(..total);

    if start.starts_with("RTSP/") || start.starts_with("HTTP/") {
        return Some(Message::Response);
    }
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let uri = parts.next().unwrap_or("").to_string();
    if method.is_empty() {
        warn!("Events channel: unparseable message start: {:?}", start);
        return Some(Message::Response);
    }
    Some(Message::Request(ReceiverRequest { method, uri, headers, body }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_request_with_a_body() {
        let mut buf = b"POST /command RTSP/1.0\r\nCSeq: 7\r\nContent-Length: 3\r\n\r\nabcPOST".to_vec();
        match take_message(&mut buf) {
            Some(Message::Request(r)) => {
                assert_eq!(r.method, "POST");
                assert_eq!(r.uri, "/command");
                assert_eq!(r.headers["cseq"], "7");
                assert_eq!(r.body, b"abc");
            }
            _ => panic!("expected a request"),
        }
        assert_eq!(buf, b"POST", "the next message's bytes must stay in the buffer");
    }

    #[test]
    fn waits_for_the_whole_body() {
        let mut buf = b"POST /command RTSP/1.0\r\nContent-Length: 5\r\n\r\nab".to_vec();
        let before = buf.len();
        assert!(take_message(&mut buf).is_none());
        assert_eq!(buf.len(), before, "nothing may be consumed yet");
    }

    fn command_request(value: &str, position: Option<f64>) -> ReceiverRequest {
        let mut params = plist::Dictionary::new();
        if let Some(p) = position {
            params.insert("kMRMediaRemoteOptionPlaybackPosition".into(), plist::Value::Real(p));
        }
        let mut dict = plist::Dictionary::new();
        dict.insert("type".into(), "sendMediaRemoteCommand".into());
        dict.insert("value".into(), value.into());
        dict.insert("params".into(), plist::Value::Dictionary(params));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &plist::Value::Dictionary(dict)).unwrap();
        ReceiverRequest { method: "POST".into(), uri: "/command".into(), headers: HashMap::new(), body }
    }

    #[test]
    fn decodes_remote_commands() {
        assert_eq!(command_request("play", None).remote_command(), Some(RemoteCommand::Play));
        assert_eq!(command_request("paus", None).remote_command(), Some(RemoteCommand::Pause));
        assert_eq!(command_request("nitm", None).remote_command(), Some(RemoteCommand::NextItem));
        assert_eq!(
            command_request("spos", Some(96.5)).remote_command(),
            Some(RemoteCommand::SetPosition(96.5))
        );
        assert_eq!(
            command_request("pitm", None).remote_command(),
            Some(RemoteCommand::Other("pitm".into()))
        );
    }

    #[test]
    fn a_seek_without_a_position_is_not_a_command() {
        assert_eq!(command_request("spos", None).remote_command(), None);
    }

    #[test]
    fn other_requests_are_not_remote_commands() {
        let mut req = command_request("play", None);
        req.uri = "/other".into();
        assert_eq!(req.remote_command(), None);
    }

    #[test]
    fn responses_are_recognised_and_skipped() {
        let mut buf = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n".to_vec();
        assert!(matches!(take_message(&mut buf), Some(Message::Response)));
        assert!(buf.is_empty());
    }
}
