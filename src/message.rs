// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa (Softium LLC)

//! Conversions between WhatsApp messages and the application-facing JSON.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use waproto::whatsapp as wa;

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn opt_b64(bytes: &Option<Vec<u8>>) -> Option<String> {
    bytes.as_deref().map(b64)
}

/// One event delivered to the application, by webhook or event stream.
#[derive(Clone, Serialize)]
pub struct Event {
    /// Stable across redeliveries of the same ciphertext; use it to
    /// deduplicate and to acknowledge.
    pub id: String,
    /// `message` or `history.sync`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub session_id: String,
    pub chat: String,
    pub sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_alt: Option<String>,
    pub message_id: String,
    /// Seconds since the epoch, from the stanza.
    pub timestamp: i64,
    pub is_from_me: bool,
    /// An earlier delivery attempt was not acknowledged.
    pub redelivered: bool,
    /// The sender's identity key changed before this message.
    pub identity_changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<MediaDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<HistoryDescriptor>,
    /// Base64 of the serialized `waE2E.Message`, the complete content.
    pub message_proto: String,
}

/// Where to download one media attachment and how to decrypt it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaDescriptor {
    /// `image`, `video`, `audio`, `document` or `sticker`.
    pub kind: String,
    pub direct_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Base64.
    pub media_key: String,
    /// Base64 SHA-256 of the plaintext file.
    pub file_sha256: String,
    /// Base64 SHA-256 of the encrypted file.
    pub file_enc_sha256: String,
    pub file_length: u64,
    pub mimetype: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// Audio and video length in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<u32>,
    /// A voice note rather than an audio file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptt: Option<bool>,
    /// Seconds since the epoch the media key was made. Defaults to now on
    /// send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_key_timestamp: Option<i64>,
}

/// A history-sync notification: where the chunk is and how to decrypt it.
/// signal-node never downloads history.
#[derive(Clone, Serialize)]
pub struct HistoryDescriptor {
    pub sync_type: Option<i32>,
    pub chunk_order: Option<u32>,
    pub progress: Option<u32>,
    pub direct_path: Option<String>,
    pub media_key: Option<String>,
    pub file_sha256: Option<String>,
    pub file_enc_sha256: Option<String>,
    pub file_length: Option<u64>,
    pub original_message_id: Option<String>,
    pub peer_data_request_session_id: Option<String>,
    /// Base64. Small initial chunks arrive inline instead of by download.
    pub inline_payload: Option<String>,
    /// Base64 of the serialized `HistorySyncNotification`.
    pub notification_proto: String,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+};
}
redacted_debug!(Event, MediaDescriptor, HistoryDescriptor, SendRequest);

/// The text a person would read: the body, or a media caption.
pub fn text_of(message: &wa::Message) -> Option<String> {
    if let Some(text) = &message.conversation {
        return Some(text.clone());
    }
    if let Some(ext) = message.extended_text_message.as_option() {
        return ext.text.clone();
    }
    None
}

macro_rules! media_descriptor {
    ($kind:literal, $m:expr, $extra:expr) => {{
        let m = $m;
        let mut d = MediaDescriptor {
            kind: $kind.to_owned(),
            direct_path: m.direct_path.clone().unwrap_or_default(),
            url: m.url.clone(),
            media_key: opt_b64(&m.media_key).unwrap_or_default(),
            file_sha256: opt_b64(&m.file_sha256).unwrap_or_default(),
            file_enc_sha256: opt_b64(&m.file_enc_sha256).unwrap_or_default(),
            file_length: m.file_length.unwrap_or_default(),
            mimetype: m.mimetype.clone().unwrap_or_default(),
            caption: None,
            file_name: None,
            width: None,
            height: None,
            seconds: None,
            ptt: None,
            media_key_timestamp: m.media_key_timestamp,
        };
        #[allow(clippy::redundant_closure_call)]
        ($extra)(&mut d, m);
        d
    }};
}

/// The first media attachment of `message`, if any.
pub fn media_of(message: &wa::Message) -> Option<MediaDescriptor> {
    if let Some(m) = message.image_message.as_option() {
        return Some(media_descriptor!(
            "image",
            m,
            |d: &mut MediaDescriptor, m: &wa::message::ImageMessage| {
                d.caption = m.caption.clone();
                d.width = m.width;
                d.height = m.height;
            }
        ));
    }
    if let Some(m) = message.video_message.as_option() {
        return Some(media_descriptor!(
            "video",
            m,
            |d: &mut MediaDescriptor, m: &wa::message::VideoMessage| {
                d.caption = m.caption.clone();
                d.width = m.width;
                d.height = m.height;
                d.seconds = m.seconds;
            }
        ));
    }
    if let Some(m) = message.audio_message.as_option() {
        return Some(media_descriptor!(
            "audio",
            m,
            |d: &mut MediaDescriptor, m: &wa::message::AudioMessage| {
                d.seconds = m.seconds;
                d.ptt = m.ptt;
            }
        ));
    }
    if let Some(m) = message.document_message.as_option() {
        return Some(media_descriptor!(
            "document",
            m,
            |d: &mut MediaDescriptor, m: &wa::message::DocumentMessage| {
                d.caption = m.caption.clone();
                d.file_name = m.file_name.clone();
            }
        ));
    }
    if let Some(m) = message.sticker_message.as_option() {
        return Some(media_descriptor!(
            "sticker",
            m,
            |d: &mut MediaDescriptor, m: &wa::message::StickerMessage| {
                d.width = m.width;
                d.height = m.height;
            }
        ));
    }
    None
}

pub fn history_descriptor(n: &wa::message::HistorySyncNotification) -> HistoryDescriptor {
    HistoryDescriptor {
        sync_type: n.sync_type.map(|t| t as i32),
        chunk_order: n.chunk_order,
        progress: n.progress,
        direct_path: n.direct_path.clone(),
        media_key: opt_b64(&n.media_key),
        file_sha256: opt_b64(&n.file_sha256),
        file_enc_sha256: opt_b64(&n.file_enc_sha256),
        file_length: n.file_length,
        original_message_id: n.original_message_id.clone(),
        peer_data_request_session_id: n.peer_data_request_session_id.clone(),
        inline_payload: opt_b64(&n.initial_hist_bootstrap_inline_payload),
        notification_proto: b64(&encode(n)),
    }
}

pub fn encode<M: waproto::buffa::Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}

/// What the application asks to send.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    /// A user (`15551234567@s.whatsapp.net`, or a LID) or a group
    /// (`...@g.us`).
    pub to: String,
    #[serde(default)]
    pub text: Option<String>,
    /// A file already encrypted and uploaded to WhatsApp's media servers.
    #[serde(default)]
    pub media: Option<MediaDescriptor>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("send exactly one of text or media")]
    NeedOneBody,
    #[error("text must not be empty")]
    EmptyText,
    #[error("media.{0} is required")]
    Missing(&'static str),
    #[error("media.{0} is not valid base64")]
    BadBase64(&'static str),
    #[error("media.{field} must be {len} bytes")]
    BadLength { field: &'static str, len: usize },
    #[error("unknown media kind {0}; use image, video, audio, document or sticker")]
    UnknownKind(String),
}

fn decode_field(value: &str, field: &'static str, len: usize) -> Result<Vec<u8>, BuildError> {
    if value.is_empty() {
        return Err(BuildError::Missing(field));
    }
    let bytes = B64
        .decode(value)
        .map_err(|_| BuildError::BadBase64(field))?;
    if bytes.len() != len {
        return Err(BuildError::BadLength { field, len });
    }
    Ok(bytes)
}

/// Build the `waE2E.Message` for a send request.
pub fn build_message(request: &SendRequest, now_secs: i64) -> Result<wa::Message, BuildError> {
    match (&request.text, &request.media) {
        (Some(text), None) => {
            if text.is_empty() {
                return Err(BuildError::EmptyText);
            }
            Ok(wa::Message {
                conversation: Some(text.clone()),
                ..Default::default()
            })
        }
        (None, Some(media)) => build_media(media, now_secs),
        _ => Err(BuildError::NeedOneBody),
    }
}

fn build_media(d: &MediaDescriptor, now_secs: i64) -> Result<wa::Message, BuildError> {
    if d.direct_path.is_empty() {
        return Err(BuildError::Missing("direct_path"));
    }
    if d.mimetype.is_empty() {
        return Err(BuildError::Missing("mimetype"));
    }
    if d.file_length == 0 {
        return Err(BuildError::Missing("file_length"));
    }
    let media_key = decode_field(&d.media_key, "media_key", 32)?;
    let file_sha256 = decode_field(&d.file_sha256, "file_sha256", 32)?;
    let file_enc_sha256 = decode_field(&d.file_enc_sha256, "file_enc_sha256", 32)?;
    let ts = Some(d.media_key_timestamp.unwrap_or(now_secs));
    let mut message = wa::Message::default();
    match d.kind.as_str() {
        "image" => {
            message.image_message = wa::message::ImageMessage {
                url: d.url.clone(),
                direct_path: Some(d.direct_path.clone()),
                media_key: Some(media_key),
                file_sha256: Some(file_sha256),
                file_enc_sha256: Some(file_enc_sha256),
                file_length: Some(d.file_length),
                mimetype: Some(d.mimetype.clone()),
                caption: d.caption.clone(),
                width: d.width,
                height: d.height,
                media_key_timestamp: ts,
                ..Default::default()
            }
            .into();
        }
        "video" => {
            message.video_message = wa::message::VideoMessage {
                url: d.url.clone(),
                direct_path: Some(d.direct_path.clone()),
                media_key: Some(media_key),
                file_sha256: Some(file_sha256),
                file_enc_sha256: Some(file_enc_sha256),
                file_length: Some(d.file_length),
                mimetype: Some(d.mimetype.clone()),
                caption: d.caption.clone(),
                width: d.width,
                height: d.height,
                seconds: d.seconds,
                media_key_timestamp: ts,
                ..Default::default()
            }
            .into();
        }
        "audio" => {
            message.audio_message = wa::message::AudioMessage {
                url: d.url.clone(),
                direct_path: Some(d.direct_path.clone()),
                media_key: Some(media_key),
                file_sha256: Some(file_sha256),
                file_enc_sha256: Some(file_enc_sha256),
                file_length: Some(d.file_length),
                mimetype: Some(d.mimetype.clone()),
                seconds: d.seconds,
                ptt: d.ptt,
                media_key_timestamp: ts,
                ..Default::default()
            }
            .into();
        }
        "document" => {
            message.document_message = wa::message::DocumentMessage {
                url: d.url.clone(),
                direct_path: Some(d.direct_path.clone()),
                media_key: Some(media_key),
                file_sha256: Some(file_sha256),
                file_enc_sha256: Some(file_enc_sha256),
                file_length: Some(d.file_length),
                mimetype: Some(d.mimetype.clone()),
                caption: d.caption.clone(),
                file_name: d.file_name.clone(),
                media_key_timestamp: ts,
                ..Default::default()
            }
            .into();
        }
        "sticker" => {
            message.sticker_message = wa::message::StickerMessage {
                url: d.url.clone(),
                direct_path: Some(d.direct_path.clone()),
                media_key: Some(media_key),
                file_sha256: Some(file_sha256),
                file_enc_sha256: Some(file_enc_sha256),
                file_length: Some(d.file_length),
                mimetype: Some(d.mimetype.clone()),
                width: d.width,
                height: d.height,
                media_key_timestamp: ts,
                ..Default::default()
            }
            .into();
        }
        other => return Err(BuildError::UnknownKind(other.to_owned())),
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> MediaDescriptor {
        MediaDescriptor {
            kind: "image".into(),
            direct_path: "/v/t62.7118-24/abc".into(),
            url: Some("https://mmg.whatsapp.net/v/t62.7118-24/abc".into()),
            media_key: b64(&[1; 32]),
            file_sha256: b64(&[2; 32]),
            file_enc_sha256: b64(&[3; 32]),
            file_length: 1234,
            mimetype: "image/jpeg".into(),
            caption: Some("look".into()),
            file_name: None,
            width: Some(10),
            height: Some(20),
            seconds: None,
            ptt: None,
            media_key_timestamp: None,
        }
    }

    #[test]
    fn text_and_media_round_trip_through_the_message() {
        let text = build_message(
            &SendRequest {
                to: "1@s.whatsapp.net".into(),
                text: Some("hi".into()),
                media: None,
            },
            0,
        )
        .unwrap();
        assert_eq!(text_of(&text).as_deref(), Some("hi"));

        let sent = image();
        let message = build_message(
            &SendRequest {
                to: "1@s.whatsapp.net".into(),
                text: None,
                media: Some(sent.clone()),
            },
            1_700_000_000,
        )
        .unwrap();
        let back = media_of(&message).unwrap();
        assert_eq!(back.media_key_timestamp, Some(1_700_000_000));
        assert_eq!(
            MediaDescriptor {
                media_key_timestamp: None,
                ..back
            },
            sent
        );
    }

    #[test]
    fn invalid_requests_are_refused() {
        let both = SendRequest {
            to: "x".into(),
            text: Some("a".into()),
            media: Some(image()),
        };
        assert_eq!(build_message(&both, 0), Err(BuildError::NeedOneBody));
        let mut short = image();
        short.media_key = b64(&[1; 5]);
        let request = SendRequest {
            to: "x".into(),
            text: None,
            media: Some(short),
        };
        assert!(matches!(
            build_message(&request, 0),
            Err(BuildError::BadLength {
                field: "media_key",
                ..
            })
        ));
        let mut odd = image();
        odd.kind = "hologram".into();
        let request = SendRequest {
            to: "x".into(),
            text: None,
            media: Some(odd),
        };
        assert!(matches!(
            build_message(&request, 0),
            Err(BuildError::UnknownKind(_))
        ));
    }
    #[test]
    fn debug_never_prints_application_text_or_descriptors() {
        let request = SendRequest {
            to: "111@s.whatsapp.net".into(),
            text: Some("private-plaintext".into()),
            media: None,
        };
        assert_eq!(format!("{request:?}"), "SendRequest(<redacted>)");
        let descriptor = MediaDescriptor {
            kind: "image".into(),
            direct_path: "/private".into(),
            media_key: "private-key".into(),
            file_sha256: "h".into(),
            file_enc_sha256: "e".into(),
            file_length: 1,
            mimetype: "image/png".into(),
            url: Some("https://private.invalid/?auth=private-auth".into()),
            caption: None,
            file_name: None,
            width: None,
            height: None,
            seconds: None,
            ptt: None,
            media_key_timestamp: None,
        };
        assert_eq!(format!("{descriptor:?}"), "MediaDescriptor(<redacted>)");
    }
}
