//! Minimal DMAP ("DAAP") tagged-item encoding for track metadata.
//!
//! AirPlay receivers show title/artist/album from a `SET_PARAMETER` request
//! with `Content-Type: application/x-dmap-tagged`. The body is a `mlit`
//! (listing item) container of tagged items. Each item is a 4-byte ASCII tag,
//! a 4-byte big-endian payload length and the payload.

/// Track fields that can be sent to a receiver's "now playing" display.
#[derive(Debug, Clone, Default)]
pub struct TrackMetadata {
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    /// Track length in milliseconds.
    pub duration_ms: Option<u32>,
}

fn push_item(out: &mut Vec<u8>, tag: &[u8; 4], payload: &[u8]) {
    out.extend_from_slice(tag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Encode `meta` as a DMAP `mlit` container.
pub fn encode_track_metadata(meta: &TrackMetadata) -> Vec<u8> {
    let mut items = Vec::new();
    // mikd: item kind, 2 = music.
    push_item(&mut items, b"mikd", &[2]);
    if let Some(title) = &meta.title {
        push_item(&mut items, b"minm", title.as_bytes());
    }
    if let Some(artist) = &meta.artist {
        push_item(&mut items, b"asar", artist.as_bytes());
    }
    if let Some(album) = &meta.album {
        push_item(&mut items, b"asal", album.as_bytes());
    }
    if let Some(ms) = meta.duration_ms {
        push_item(&mut items, b"astm", &ms.to_be_bytes());
    }

    let mut out = Vec::with_capacity(items.len() + 8);
    push_item(&mut out, b"mlit", &items);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_container_and_items() {
        let meta = TrackMetadata {
            title: Some("Song".into()),
            artist: Some("Band".into()),
            album: None,
            duration_ms: Some(0x0001_0203),
        };
        let bytes = encode_track_metadata(&meta);

        // Outer container.
        assert_eq!(&bytes[0..4], b"mlit");
        let outer_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        assert_eq!(outer_len, bytes.len() - 8);

        let body = &bytes[8..];
        // mikd (1 byte), minm "Song", asar "Band", astm (4 bytes).
        let expected: Vec<u8> = [
            &b"mikd"[..], &[0, 0, 0, 1], &[2],
            b"minm", &[0, 0, 0, 4], b"Song",
            b"asar", &[0, 0, 0, 4], b"Band",
            b"astm", &[0, 0, 0, 4], &[0x00, 0x01, 0x02, 0x03],
        ]
        .concat();
        assert_eq!(body, expected.as_slice());
    }

    #[test]
    fn utf8_length_is_in_bytes() {
        let meta = TrackMetadata { title: Some("Ä".into()), ..Default::default() };
        let bytes = encode_track_metadata(&meta);
        // mlit header (8) + mikd (9) + minm header (8) + 2 UTF-8 bytes.
        let minm_len_at = 8 + 9 + 4;
        assert_eq!(&bytes[minm_len_at..minm_len_at + 4], &[0, 0, 0, 2]);
    }
}
