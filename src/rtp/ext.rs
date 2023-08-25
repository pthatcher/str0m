use std::collections::VecDeque;
use std::fmt;
use std::str::from_utf8;

use super::mtime::MediaTime;
use super::{Mid, Rid};

/// RTP header extensions.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Extension {
    /// <http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time>
    AbsoluteSendTime,
    /// <urn:ietf:params:rtp-hdrext:ssrc-audio-level>
    AudioLevel,
    /// <urn:ietf:params:rtp-hdrext:toffset>
    ///
    /// Use when a RTP packet is delayed by a send queue to indicate an offset in the "transmitter".
    /// It effectively means we can set a timestamp offset exactly when the UDP packet leaves the
    /// server.
    TransmissionTimeOffset,
    /// <urn:3gpp:video-orientation>
    VideoOrientation,
    /// <http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01>
    TransportSequenceNumber,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/playout-delay>
    PlayoutDelay,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/video-content-type>
    VideoContentType,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/video-timing>
    VideoTiming,
    /// <urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id>
    ///
    /// UTF8 encoded identifier for the RTP stream. Not the same as SSRC, this is is designed to
    /// avoid running out of SSRC for very large sessions.
    RtpStreamId,
    /// <urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id>
    ///
    /// UTF8 encoded identifier referencing another RTP stream's RtpStreamId. If we see
    /// this extension type, we know the stream is a repair stream.
    RepairedRtpStreamId,
    /// <urn:ietf:params:rtp-hdrext:sdes:mid>
    RtpMid,
    /// <http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07>
    FrameMarking,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/color-space>
    ColorSpace,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/video-layers-allocation00>
    VideoLayersAllocation,
    /// Not recognized URI
    UnknownUri,
}

/// Mapping of extension URI to our enum
const EXT_URI: &[(Extension, &str)] = &[
    (
        Extension::AbsoluteSendTime,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
    ),
    (
        Extension::AudioLevel,
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
    ),
    (
        Extension::TransmissionTimeOffset,
        "urn:ietf:params:rtp-hdrext:toffset",
    ),
    (
        Extension::VideoOrientation, //
        "urn:3gpp:video-orientation",
    ),
    (
        Extension::TransportSequenceNumber,
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    ),
    (
        Extension::PlayoutDelay,
        "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
    ),
    (
        Extension::VideoContentType,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-content-type",
    ),
    (
        Extension::VideoTiming,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-timing",
    ),
    (
        Extension::RtpStreamId,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
    ),
    (
        Extension::RepairedRtpStreamId,
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ),
    (
        Extension::RtpMid, //
        "urn:ietf:params:rtp-hdrext:sdes:mid",
    ),
    (
        Extension::FrameMarking,
        "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07",
    ),
    (
        Extension::ColorSpace,
        "http://www.webrtc.org/experiments/rtp-hdrext/color-space",
    ),
    (
        Extension::VideoLayersAllocation,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-layers-allocation00",
    ),
];

impl Extension {
    /// Parses an extension from a URI.
    pub fn from_uri(uri: &str) -> Self {
        for (t, spec) in EXT_URI.iter() {
            if *spec == uri {
                return *t;
            }
        }

        trace!("Unknown a=extmap uri: {}", uri);

        Extension::UnknownUri
    }

    /// Represents the extension as an URI.
    pub fn as_uri(&self) -> &'static str {
        for (t, spec) in EXT_URI.iter() {
            if t == self {
                return spec;
            }
        }
        "unknown"
    }

    pub(crate) fn is_serialized(&self) -> bool {
        *self != Extension::UnknownUri
    }

    fn is_audio(&self) -> bool {
        use Extension::*;
        matches!(
            self,
            RtpStreamId
                | RepairedRtpStreamId
                | RtpMid
                | AbsoluteSendTime
                | AudioLevel
                | TransportSequenceNumber
                | TransmissionTimeOffset
                | PlayoutDelay
        )
    }

    fn is_video(&self) -> bool {
        use Extension::*;
        matches!(
            self,
            RtpStreamId
                | RepairedRtpStreamId
                | RtpMid
                | AbsoluteSendTime
                | VideoOrientation
                | TransportSequenceNumber
                | TransmissionTimeOffset
                | PlayoutDelay
                | VideoContentType
                | VideoTiming
                | FrameMarking
                | ColorSpace
                | VideoLayersAllocation
        )
    }
}

// As of 2022-09-28, for audio google chrome offers these.
// "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level"
// "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
// "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
// "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid"
//
// For video these.
// "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
// "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
// "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid"
// "a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay"
// "a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type"
// "a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing"
// "a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space"
// "a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
// "a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id"
// "a=extmap:13 urn:3gpp:video-orientation"
// "a=extmap:14 urn:ietf:params:rtp-hdrext:toffset"

/// Mapping between RTP extension id to what extension that is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExtensionMap([Option<MapEntry>; 14]); // index 0 is extmap:1.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MapEntry {
    ext: Extension,
    locked: bool,
}

impl ExtensionMap {
    /// Create an empty map.
    pub fn empty() -> Self {
        ExtensionMap([None; 14])
    }

    /// Creates a map with the "standard" mappings.
    ///
    /// The standard are taken from Chrome.
    pub fn standard() -> Self {
        let mut exts = Self::empty();

        exts.set(1, Extension::AudioLevel);
        exts.set(2, Extension::AbsoluteSendTime);
        exts.set(3, Extension::TransportSequenceNumber);
        exts.set(4, Extension::RtpMid);
        exts.set(6, Extension::VideoLayersAllocation);
        // exts.set_mapping(&ExtMap::new(8, Extension::ColorSpace));
        exts.set(10, Extension::RtpStreamId);
        exts.set(11, Extension::RepairedRtpStreamId);
        exts.set(13, Extension::VideoOrientation);

        exts
    }

    pub(crate) fn clear(&mut self) {
        for i in &mut self.0 {
            *i = None;
        }
    }

    /// Set a mapping for an extension.
    ///
    /// The id must be 1-14 inclusive (1-indexed).
    pub fn set(&mut self, id: u8, ext: Extension) {
        if id < 1 || id > 14 {
            debug!("Set RTP extension out of range 1-14: {}", id);
            return;
        }
        let idx = id as usize - 1;

        let m = MapEntry { ext, locked: false };

        self.0[idx] = Some(m);
    }

    /// Look up the extension for the id.
    ///
    /// The id must be 1-14 inclusive (1-indexed).
    pub fn lookup(&self, id: u8) -> Option<Extension> {
        if id >= 1 && id <= 14 {
            self.0[id as usize - 1].map(|m| m.ext)
        } else {
            debug!("Lookup RTP extension out of range 1-14: {}", id);
            None
        }
    }

    /// Finds the id for an extension (if mapped).
    ///
    /// The returned id will be 1-based.
    pub fn id_of(&self, e: Extension) -> Option<u8> {
        self.0
            .iter()
            .position(|x| x.map(|e| e.ext) == Some(e))
            .map(|p| p as u8 + 1)
    }

    /// Returns an iterator over the elements of the extension map
    ///
    /// Filtering them based on the provided `audio` flag
    pub fn iter(&self, audio: bool) -> impl Iterator<Item = (u8, Extension)> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i, e)))
            .filter(move |(_, e)| {
                if audio {
                    e.ext.is_audio()
                } else {
                    e.ext.is_video()
                }
            })
            .map(|(i, e)| ((i + 1) as u8, e.ext))
    }

    pub(crate) fn cloned_with_type(&self, audio: bool) -> Self {
        let mut x = ExtensionMap::empty();
        for (id, ext) in self.iter(audio) {
            x.set(id, ext);
        }
        x
    }

    // https://tools.ietf.org/html/rfc5285
    pub(crate) fn parse(
        &self,
        mut buf: &[u8],
        two_byte_header: bool,
        ext_vals: &mut ExtensionValues,
    ) {
        loop {
            if buf.is_empty() {
                return;
            }

            if buf[0] == 0 {
                // padding
                buf = &buf[1..];
                continue;
            }

            let (id, len) = if two_byte_header {
                if buf.len() < 2 {
                    return;
                }
                let id = buf[0];
                let len = buf[1] as usize;
                buf = &buf[2..];
                (id, len)
            } else {
                let id = buf[0] >> 4;
                let len = (buf[0] & 0xf) as usize + 1;
                if id == 15 {
                    // If the ID value 15 is
                    // encountered, its length field should be ignored, processing of the
                    // entire extension should terminate at that point, and only the
                    // extension elements present prior to the element with ID 15
                    // considered.
                    return;
                }
                buf = &buf[1..];
                (id, len)
            };

            if buf.len() < len {
                trace!("Not enough type ext len: {} < {}", buf.len(), len);
                return;
            }

            let ext_buf = &buf[..len];
            if let Some(ext) = self.lookup(id) {
                ext.parse_value(ext_buf, ext_vals);
            }

            buf = &buf[len..];
        }
    }

    pub(crate) fn write_to(&self, ext_buf: &mut [u8], ev: &ExtensionValues) -> usize {
        let orig_len = ext_buf.len();
        let mut b = ext_buf;

        for (idx, x) in self.0.iter().enumerate() {
            if let Some(v) = x {
                if let Some(n) = v.ext.write_to(&mut b[1..], ev) {
                    assert!(n <= 16);
                    assert!(n > 0);
                    b[0] = (idx as u8 + 1) << 4 | (n as u8 - 1);
                    b = &mut b[1 + n..];
                }
            }
        }

        orig_len - b.len()
    }

    pub(crate) fn remap(&mut self, remote_exts: &[(u8, Extension)]) {
        // Match remote numbers and lock down those we see for the first time.
        for (id, ext) in remote_exts {
            self.swap(*id, *ext);
        }
    }

    fn swap(&mut self, id: u8, ext: Extension) {
        if id < 1 || id > 14 {
            return;
        }

        // Mapping goes from 0 to 13.
        let new_index = id as usize - 1;

        let Some(old_index) = self
            .0
            .iter()
            .enumerate()
            .find(|(_, m)| m.map(|m| m.ext) == Some(ext))
            .map(|(i, _)| i)
        else {
            return;
        };

        // Unwrap OK because index is checking just above.
        let old = self.0[old_index].as_mut().unwrap();

        let is_change = new_index != old_index;

        // If either audio or video is locked, we got a previous extmap negotiation.
        if is_change && old.locked {
            warn!(
                "Extmap locked by previous negotiation. Ignore change: {} -> {}",
                old_index, new_index
            );
            return;
        }

        // Locking must be done regardless of whether there was an actual change.
        old.locked = true;

        if !is_change {
            return;
        }

        self.0.swap(old_index, new_index);
    }
}

const FIXED_POINT_6_18: i64 = 262_144; // 2 ^ 18

impl Extension {
    pub(crate) fn write_to(&self, buf: &mut [u8], ev: &ExtensionValues) -> Option<usize> {
        use Extension::*;
        match self {
            AbsoluteSendTime => {
                // 24 bit fixed point 6 bits for seconds, 18 for the decimals.
                // wraps around at 64 seconds.
                let v = ev.abs_send_time?.rebase(FIXED_POINT_6_18);
                let time_24 = v.numer() as u32;
                buf[..3].copy_from_slice(&time_24.to_be_bytes()[1..]);
                Some(3)
            }
            AudioLevel => {
                let v1 = ev.audio_level?;
                let v2 = ev.voice_activity?;
                buf[0] = if v2 { 0x80 } else { 0 } | (-(0x7f & v1) as u8);
                Some(1)
            }
            TransmissionTimeOffset => {
                let v = ev.tx_time_offs?;
                buf[..4].copy_from_slice(&v.to_be_bytes());
                Some(4)
            }
            VideoOrientation => {
                let v = ev.video_orientation?;
                buf[0] = v as u8;
                Some(1)
            }
            TransportSequenceNumber => {
                let v = ev.transport_cc?;
                buf[..2].copy_from_slice(&v.to_be_bytes());
                Some(2)
            }
            PlayoutDelay => {
                let v1 = ev.play_delay_min?.rebase(100);
                let v2 = ev.play_delay_max?.rebase(100);
                let min = (v1.numer() & 0xfff) as u32;
                let max = (v2.numer() & 0xfff) as u32;
                buf[0] = (min >> 4) as u8;
                buf[1] = (min << 4) as u8 | (max >> 8) as u8;
                buf[2] = max as u8;
                Some(3)
            }
            VideoContentType => {
                let v = ev.video_content_type?;
                buf[0] = v;
                Some(1)
            }
            VideoTiming => {
                let v = ev.video_timing?;
                buf[0] = v.flags;
                buf[1..3].copy_from_slice(&v.encode_start.to_be_bytes());
                buf[3..5].copy_from_slice(&v.encode_finish.to_be_bytes());
                buf[5..7].copy_from_slice(&v.packetize_complete.to_be_bytes());
                buf[7..9].copy_from_slice(&v.last_left_pacer.to_be_bytes());
                // Reserved for network
                buf[9..11].copy_from_slice(&0_u16.to_be_bytes());
                buf[11..13].copy_from_slice(&0_u16.to_be_bytes());
                Some(13)
            }
            RtpStreamId => {
                let v = ev.rid?;
                let l = v.as_bytes().len();
                buf[..l].copy_from_slice(v.as_bytes());
                Some(l)
            }
            RepairedRtpStreamId => {
                let v = ev.rid_repair?;
                let l = v.as_bytes().len();
                buf[..l].copy_from_slice(v.as_bytes());
                Some(l)
            }
            RtpMid => {
                let v = ev.mid?;
                let l = v.as_bytes().len();
                buf[..l].copy_from_slice(v.as_bytes());
                Some(l)
            }
            FrameMarking => {
                let v = ev.frame_mark?;
                buf[..4].copy_from_slice(&v.to_be_bytes());
                Some(4)
            }
            ColorSpace => {
                // TODO HDR color space
                todo!()
            }
            VideoLayersAllocation => {
                // TODO VLA
                None
            }
            UnknownUri => {
                // do nothing
                todo!()
            }
        }
    }

    pub(crate) fn parse_value(&self, buf: &[u8], v: &mut ExtensionValues) -> Option<()> {
        use Extension::*;
        match self {
            // 3
            AbsoluteSendTime => {
                // fixed point 6.18
                if buf.len() < 3 {
                    return None;
                }
                let time_24 = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
                v.abs_send_time = Some(MediaTime::new(time_24 as i64, FIXED_POINT_6_18));
            }
            // 1
            AudioLevel => {
                if buf.is_empty() {
                    return None;
                }
                v.audio_level = Some(-(0x7f & buf[0] as i8));
                v.voice_activity = Some(buf[0] & 0x80 > 0);
            }
            // 3
            TransmissionTimeOffset => {
                if buf.len() < 4 {
                    return None;
                }
                v.tx_time_offs = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            // 1
            VideoOrientation => {
                if buf.is_empty() {
                    return None;
                }
                v.video_orientation = Some(super::ext::VideoOrientation::from(buf[0] & 3));
            }
            // 2
            TransportSequenceNumber => {
                if buf.len() < 2 {
                    return None;
                }
                v.transport_cc = Some(u16::from_be_bytes([buf[0], buf[1]]));
            }
            // 3
            PlayoutDelay => {
                if buf.len() < 3 {
                    return None;
                }
                let min = (buf[0] as u32) << 4 | (buf[1] as u32) >> 4;
                let max = ((buf[1] & 0xf) as u32) << 8 | buf[2] as u32;
                v.play_delay_min = Some(MediaTime::new(min as i64, 100));
                v.play_delay_max = Some(MediaTime::new(max as i64, 100));
            }
            // 1
            VideoContentType => {
                if buf.is_empty() {
                    return None;
                }
                v.video_content_type = Some(buf[0]);
            }
            // 13
            VideoTiming => {
                if buf.len() < 9 {
                    return None;
                }
                v.video_timing = Some(self::VideoTiming {
                    flags: buf[0],
                    encode_start: u16::from_be_bytes([buf[1], buf[2]]),
                    encode_finish: u16::from_be_bytes([buf[3], buf[4]]),
                    packetize_complete: u16::from_be_bytes([buf[5], buf[6]]),
                    last_left_pacer: u16::from_be_bytes([buf[7], buf[8]]),
                    //  9 - 10 // reserved for network
                    // 11 - 12 // reserved for network
                });
            }
            RtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.rid = Some(s.into());
            }
            RepairedRtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.rid_repair = Some(s.into());
            }
            RtpMid => {
                let s = from_utf8(buf).ok()?;
                v.mid = Some(s.into());
            }
            FrameMarking => {
                if buf.len() < 4 {
                    return None;
                }
                v.frame_mark = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            ColorSpace => {
                // TODO HDR color space
            }
            VideoLayersAllocation => {
                v.video_layers_allocation = self::VideoLayersAllocation::parse(buf);
            }
            UnknownUri => {
                // ignore
            }
        }

        Some(())
    }
}

/// Values in an RTP header extension.
///
/// This is metadata that is available also without decrypting the SRTP packets.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExtensionValues {
    /// Audio level is measured in negative decibel. 0 is max and a "normal" value might be -30.
    pub audio_level: Option<i8>,

    /// Indication that there is sound from a voice.
    pub voice_activity: Option<bool>,

    /// Tell a receiver what rotation a video need to replay correctly.
    pub video_orientation: Option<VideoOrientation>,

    // The values below are considered internal until we have a reason to expose them.
    // Generally we want to avoid expose experimental features unless there are strong
    // reasons to do so.
    #[doc(hidden)]
    pub video_content_type: Option<u8>, // 0 = unspecified, 1 = screenshare
    #[doc(hidden)]
    pub tx_time_offs: Option<u32>,
    #[doc(hidden)]
    pub abs_send_time: Option<MediaTime>,
    #[doc(hidden)]
    pub transport_cc: Option<u16>, // (buf[0] << 8) | buf[1];
    #[doc(hidden)]
    // https://webrtc.googlesource.com/src/+/refs/heads/master/docs/native-code/rtp-hdrext/playout-delay
    pub play_delay_min: Option<MediaTime>,
    #[doc(hidden)]
    pub play_delay_max: Option<MediaTime>,
    #[doc(hidden)]
    pub video_timing: Option<VideoTiming>,
    #[doc(hidden)]
    pub rid: Option<Rid>,
    #[doc(hidden)]
    pub rid_repair: Option<Rid>,
    #[doc(hidden)]
    pub mid: Option<Mid>,
    #[doc(hidden)]
    pub frame_mark: Option<u32>,
    #[doc(hidden)]
    pub video_layers_allocation: Option<VideoLayersAllocation>,
}

impl fmt::Debug for ExtensionValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtensionValues {{")?;

        if let Some(t) = self.mid {
            write!(f, " mid: {t}")?;
        }
        if let Some(t) = self.rid {
            write!(f, " rid: {t}")?;
        }
        if let Some(t) = self.rid_repair {
            write!(f, " rid_repair: {t}")?;
        }
        if let Some(t) = self.abs_send_time {
            write!(f, " abs_send_time: {:?}", t)?;
        }
        if let Some(t) = self.voice_activity {
            write!(f, " voice_activity: {t}")?;
        }
        if let Some(t) = self.audio_level {
            write!(f, " audio_level: {t}")?;
        }
        if let Some(t) = self.tx_time_offs {
            write!(f, " tx_time_offs: {t}")?;
        }
        if let Some(t) = self.video_orientation {
            write!(f, " video_orientation: {t:?}")?;
        }
        if let Some(t) = self.transport_cc {
            write!(f, " transport_cc: {t}")?;
        }
        if let Some(t) = self.play_delay_min {
            write!(f, " play_delay_min: {}", t.as_seconds())?;
        }
        if let Some(t) = self.play_delay_max {
            write!(f, " play_delay_max: {}", t.as_seconds())?;
        }
        if let Some(t) = self.video_content_type {
            write!(f, " video_content_type: {t}")?;
        }
        if let Some(t) = &self.video_timing {
            write!(f, " video_timing: {t:?}")?;
        }
        if let Some(t) = &self.frame_mark {
            write!(f, " frame_mark: {t}")?;
        }

        write!(f, " }}")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoTiming {
    // 0x01 = extension is set due to timer.
    // 0x02 - extension is set because the frame is larger than usual.
    pub flags: u8,
    pub encode_start: u16,
    pub encode_finish: u16,
    pub packetize_complete: u16,
    pub last_left_pacer: u16,
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Extension::*;
        write!(
            f,
            "{}",
            match self {
                AbsoluteSendTime => "abs-send-time",
                AudioLevel => "ssrc-audio-level",
                TransmissionTimeOffset => "toffset",
                VideoOrientation => "video-orientation",
                TransportSequenceNumber => "transport-wide-cc",
                PlayoutDelay => "playout-delay",
                VideoContentType => "video-content-type",
                VideoTiming => "video-timing",
                RtpStreamId => "rtp-stream-id",
                RepairedRtpStreamId => "repaired-rtp-stream-id",
                RtpMid => "mid",
                FrameMarking => "frame-marking07",
                ColorSpace => "color-space",
                VideoLayersAllocation => "video-layers-allocation",
                UnknownUri => "unknown-uri",
            }
        )
    }
}

impl fmt::Debug for ExtensionMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extensions(")?;
        let joined = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.map(|v| (i + 1, v)))
            .map(|(i, v)| format!("{}={}", i, v.ext))
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{joined}")?;
        write!(f, ")")?;
        Ok(())
    }
}

/// How the video is rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoOrientation {
    /// Not rotated.
    Deg0 = 0,
    /// 90 degress clockwise.
    Deg90 = 3,
    /// Upside down.
    Deg180 = 2,
    /// 90 degrees counter clockwise.
    Deg270 = 1,
}

impl From<u8> for VideoOrientation {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Deg270,
            2 => Self::Deg180,
            3 => Self::Deg90,
            _ => Self::Deg0,
        }
    }
}

/// Video Layers Allocation RTP Header Extension
/// See https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/video-layers-allocation00
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VideoLayersAllocation {
    /// Erroneously called "RID" in the spec.
    /// AKA RTP stream index
    /// Set to 0 when everything is inactive (the special case of the header extension being just 0).
    pub current_simulcast_stream_index: u8,

    /// AKA RTP streams
    pub simulcast_streams: Vec<SimulcastStreamAllocation>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SimulcastStreamAllocation {
    pub spatial_layers: Vec<SpatialLayerAllocation>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SpatialLayerAllocation {
    /// If empty, the spatial layer is not active.
    pub temporal_layers: Vec<TemporalLayerAllocation>,
    pub resolution_and_framerate: Option<ResolutionAndFramerate>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TemporalLayerAllocation {
    // Cumulative across the temporal layers within a spatial layer
    pub cumulative_kbps: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolutionAndFramerate {
    pub width: u16,
    pub height: u16,
    pub framerate: u8,
}

impl VideoLayersAllocation {
    #[allow(dead_code)]
    fn parse(buf: &[u8]) -> Option<Self> {
        // First byte
        let (&b0, after_b0) = buf.split_first()?;
        if b0 == 0u8 && after_b0.is_empty() {
            // Special case when everything is inactive.
            return Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![],
            });
        }
        let current_simulcast_stream_index = read_bits(b0, 0..2);
        let simulcast_stream_count = read_bits(b0, 2..4) + 1;
        let shared_spatial_layer_bitmask = read_bits(b0, 4..8);

        // Spatial layer bitmasks
        let (spatial_layer_actives, after_spatial_layer_bitmasks) =
            if shared_spatial_layer_bitmask > 0 {
                let shared_spatial_layer_actives =
                    truncated_bools_from_lower_4bits(shared_spatial_layer_bitmask);
                let spatial_layer_actives =
                    vec![shared_spatial_layer_actives; simulcast_stream_count as usize];
                let after_spatial_layer_bitmasks = after_b0;
                (spatial_layer_actives, after_spatial_layer_bitmasks)
            } else {
                // 4 bits per simulcast stream
                let (spatial_layer_bitmasks, after_spatial_layer_bitmasks) =
                    split_at(after_b0, div_round_up(simulcast_stream_count as usize, 2))?;
                let spatial_layer_actives = spatial_layer_bitmasks
                    .iter()
                    .flat_map(|&byte| split_byte_in2(byte))
                    .take(simulcast_stream_count as usize)
                    .map(truncated_bools_from_lower_4bits)
                    .collect();
                (spatial_layer_actives, after_spatial_layer_bitmasks)
            };
        let total_active_spatial_layer_count = spatial_layer_actives
            .iter()
            .flatten()
            .filter(|&&active| active)
            .count();

        // Temporal layer counts
        // 2 bits per temporal layer
        let (temporal_layer_counts, after_temporal_layer_counts) = split_at(
            after_spatial_layer_bitmasks,
            div_round_up(total_active_spatial_layer_count, 4),
        )?;
        let mut temporal_layer_counts: VecDeque<u8> = temporal_layer_counts
            .iter()
            .flat_map(|&byte| split_byte_in4(byte))
            .map(|count_minus_1| count_minus_1 + 1)
            .take(total_active_spatial_layer_count)
            .collect();
        let total_temporal_layer_count = temporal_layer_counts.iter().sum();

        // Temporal layer bitrates
        let mut next_temporal_layer_bitrate = after_temporal_layer_counts;
        let mut temporal_layer_bitrates: VecDeque<u64> = (0..total_temporal_layer_count)
            .map(|_temporal_layer_index| {
                let (bitrate, after_temporal_layer_bitrate) =
                    parse_leb_u64(next_temporal_layer_bitrate);
                next_temporal_layer_bitrate = after_temporal_layer_bitrate;
                bitrate
            })
            .collect();

        // (Optional) resolutions and framerates
        let mut next_resolution_and_framerate = next_temporal_layer_bitrate;
        let mut resolutions_and_framerates: VecDeque<ResolutionAndFramerate> = (0
            ..total_active_spatial_layer_count)
            .filter_map(|_| {
                let (resolution_and_framerate, after_resolution_and_framerate) =
                    split_at(next_resolution_and_framerate, 5)?;
                next_resolution_and_framerate = after_resolution_and_framerate;
                Some(ResolutionAndFramerate {
                    width: u16::from_be_bytes(resolution_and_framerate[0..2].try_into().unwrap())
                        + 1,
                    height: u16::from_be_bytes(resolution_and_framerate[2..4].try_into().unwrap())
                        + 1,
                    framerate: resolution_and_framerate[4],
                })
            })
            .collect();

        let simulcast_streams = spatial_layer_actives
            .into_iter()
            .map(|spatial_layer_actives| {
                let spatial_layers = spatial_layer_actives
                    .into_iter()
                    .filter_map(|spatial_layer_active| {
                        let (temporal_layers, resolution_and_framerate) = if spatial_layer_active {
                            let temporal_layer_count = temporal_layer_counts.pop_front()?;
                            let temporal_layers = (0..temporal_layer_count)
                                .filter_map(|_temporal_layer_index| {
                                    Some(TemporalLayerAllocation {
                                        cumulative_kbps: temporal_layer_bitrates.pop_front()?,
                                    })
                                })
                                .collect();
                            let resolution_and_framerate = resolutions_and_framerates.pop_front();
                            (temporal_layers, resolution_and_framerate)
                        } else {
                            (vec![], None)
                        };
                        Some(SpatialLayerAllocation {
                            temporal_layers,
                            resolution_and_framerate,
                        })
                    })
                    .collect();
                SimulcastStreamAllocation { spatial_layers }
            })
            .collect();
        Some(VideoLayersAllocation {
            current_simulcast_stream_index,
            simulcast_streams,
        })
    }
}

// returns (value, rest)
#[allow(dead_code)]
fn parse_leb_u64(bytes: &[u8]) -> (u64, &[u8]) {
    let mut result = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        let is_last = !read_bit(byte, 0);
        let chunk = read_bits(byte, 1..8);
        result |= (chunk as u64) << (7 * index);
        if is_last {
            return (result, &bytes[(index + 1)..]);
        }
    }
    (0, bytes)
}

// If successful, the size of the left will be mid,
// and the size of the right while be buf.len()-mid.
#[allow(dead_code)]
fn split_at(buf: &[u8], mid: usize) -> Option<(&[u8], &[u8])> {
    if mid > buf.len() {
        return None;
    }
    Some(buf.split_at(mid))
}

#[allow(dead_code)]
fn div_round_up(top: usize, bottom: usize) -> usize {
    if top == 0 {
        0
    } else {
        ((top - 1) / bottom) + 1
    }
}

#[allow(dead_code)]
fn split_byte_in2(byte: u8) -> [u8; 2] {
    [read_bits(byte, 0..4), read_bits(byte, 4..8)]
}

#[allow(dead_code)]
fn split_byte_in4(byte: u8) -> [u8; 4] {
    [
        read_bits(byte, 0..2),
        read_bits(byte, 2..4),
        read_bits(byte, 4..6),
        read_bits(byte, 6..8),
    ]
}

fn truncated_bools_from_lower_4bits(bits: u8) -> Vec<bool> {
    let mut count = 0;
    let mut bools: Vec<bool> = (0..=3u8)
        .map(|index| {
            let high = read_bit(bits, 7 - index);
            if high {
                count = index + 1;
            }
            high
        })
        .collect();
    bools.truncate(count as usize);
    bools
}

#[allow(dead_code)]
fn read_bit(bits: u8, index: u8) -> bool {
    read_bits(bits, index..(index + 1)) > 0
}

#[allow(dead_code)]
fn read_bits(bits: u8, range: std::ops::Range<u8>) -> u8 {
    assert!(range.end <= 8);
    (bits >> (8 - range.end)) & (0b1111_1111 >> (8 - range.len()))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn abs_send_time() {
        let mut exts = ExtensionMap::empty();
        exts.set(4, Extension::AbsoluteSendTime);
        let ev = ExtensionValues {
            abs_send_time: Some(MediaTime::new(1, FIXED_POINT_6_18)),
            ..Default::default()
        };

        let mut buf = vec![0_u8; 8];
        exts.write_to(&mut buf[..], &ev);

        let mut ev2 = ExtensionValues::default();
        exts.parse(&buf, false, &mut ev2);

        assert_eq!(ev.abs_send_time, ev2.abs_send_time);
    }

    #[test]
    fn playout_delay() {
        let mut exts = ExtensionMap::empty();
        exts.set(2, Extension::PlayoutDelay);
        let ev = ExtensionValues {
            play_delay_min: Some(MediaTime::new(100, 100)),
            play_delay_max: Some(MediaTime::new(200, 100)),
            ..Default::default()
        };

        let mut buf = vec![0_u8; 8];
        exts.write_to(&mut buf[..], &ev);

        let mut ev2 = ExtensionValues::default();
        exts.parse(&buf, false, &mut ev2);

        assert_eq!(ev.play_delay_min, ev2.play_delay_min);
        assert_eq!(ev.play_delay_max, ev2.play_delay_max);
    }

    #[test]
    fn remap_exts_audio() {
        use Extension::*;

        let mut e1 = ExtensionMap::standard();
        let mut e2 = ExtensionMap::empty();
        e2.set(14, TransportSequenceNumber);

        println!("{:?}", e1.iter(false).collect::<Vec<_>>());

        e1.remap(&e2.iter(true).collect::<Vec<_>>());

        // e1 should have adjusted the TransportSequenceNumber for audio
        assert_eq!(
            e1.iter(true).collect::<Vec<_>>(),
            vec![
                (1, AudioLevel),
                (2, AbsoluteSendTime),
                (4, RtpMid),
                (10, RtpStreamId),
                (11, RepairedRtpStreamId),
                (14, TransportSequenceNumber)
            ]
        );

        // e1 should have adjusted the TransportSequenceNumber for vudeo
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![
                (2, AbsoluteSendTime),
                (4, RtpMid),
                (6, VideoLayersAllocation),
                (10, RtpStreamId),
                (11, RepairedRtpStreamId),
                (13, VideoOrientation),
                (14, TransportSequenceNumber),
            ]
        );
    }

    #[test]
    fn remap_exts_video() {
        use Extension::*;

        let mut e1 = ExtensionMap::empty();
        e1.set(3, TransportSequenceNumber);
        e1.set(4, VideoOrientation);
        e1.set(5, VideoContentType);
        let mut e2 = ExtensionMap::empty();
        e2.set(14, TransportSequenceNumber);
        e2.set(12, VideoOrientation);

        e1.remap(&e2.iter(false).collect::<Vec<_>>());

        // e1 should have adjusted to e2.
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![
                (5, VideoContentType),
                (12, VideoOrientation),
                (14, TransportSequenceNumber)
            ]
        );
    }

    #[test]
    fn remap_exts_swaparoo() {
        use Extension::*;

        let mut e1 = ExtensionMap::empty();
        e1.set(12, TransportSequenceNumber);
        e1.set(14, VideoOrientation);
        let mut e2 = ExtensionMap::empty();
        e2.set(14, TransportSequenceNumber);
        e2.set(12, VideoOrientation);

        e1.remap(&e2.iter(false).collect::<Vec<_>>());

        // just make sure the logic isn't wrong for 12-14 -> 14-12
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![(12, VideoOrientation), (14, TransportSequenceNumber)]
        );
    }

    #[test]
    fn remap_exts_illegal() {
        use Extension::*;

        let mut e1 = ExtensionMap::empty();
        e1.set(12, TransportSequenceNumber);
        e1.set(14, VideoOrientation);

        let mut e2 = ExtensionMap::empty();
        e2.set(14, TransportSequenceNumber);
        e2.set(12, VideoOrientation);

        let mut e3 = ExtensionMap::empty();
        // Illegal change of already negotiated/locked number
        e3.set(1, TransportSequenceNumber);
        e3.set(12, AudioLevel); // change of type for existing.

        // First apply e2
        e1.remap(&e2.iter(false).collect::<Vec<_>>());

        println!("{:#?}", e1.0);
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![(12, VideoOrientation), (14, TransportSequenceNumber)]
        );

        // Now attempt e3
        e1.remap(&e3.iter(true).collect::<Vec<_>>());

        println!("{:#?}", e1.0);
        // At this point we should have not allowed the change, but remain as it was in first apply.
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![(12, VideoOrientation), (14, TransportSequenceNumber)]
        );
    }

    #[test]
    fn test_read_bits() {
        assert_eq!(read_bits(0b1100_0000, 0..2), 0b0000_0011);
        assert_eq!(read_bits(0b1001_0101, 0..2), 0b0000_0010);
        assert_eq!(read_bits(0b0110_1010, 0..2), 0b0000_0001);
        assert_eq!(read_bits(0b0011_1111, 0..2), 0b0000_0000);
        assert_eq!(read_bits(0b0011_0000, 2..4), 0b0000_0011);
        assert_eq!(read_bits(0b0110_0101, 2..4), 0b0000_0010);
        assert_eq!(read_bits(0b1001_1010, 2..4), 0b0000_0001);
        assert_eq!(read_bits(0b1100_1111, 2..4), 0b0000_0000);
    }

    #[test]
    fn test_parse_leb_u64() {
        let (value, rest) = parse_leb_u64(&[0b0000_0000, 5]);
        assert_eq!(0, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u64(&[0b0000_0001, 5]);
        assert_eq!(1, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u64(&[0b1000_0000, 0b0000_0001, 5]);
        assert_eq!(128, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u64(&[0b1000_0000, 0b1000_0000, 0b0000_0001, 5]);
        assert_eq!(16384, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u64(&[0b1000_0000, 0b1000_0000, 0b1000_0000, 0b0000_0001, 5]);
        assert_eq!(2097152, value);
        assert_eq!(&[5], rest);
    }

    #[test]
    fn test_parse_vla_empty_buffer() {
        assert_eq!(VideoLayersAllocation::parse(&[]), None);
    }

    #[test]
    fn test_parse_vla_empty() {
        assert_eq!(
            VideoLayersAllocation::parse(&[0b0000_0000]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![],
            })
        );
    }

    #[test]
    fn test_parse_vla_missing_spatial_layer_bitmasks() {
        assert_eq!(VideoLayersAllocation::parse(&[0b0110_0000]), None);
    }

    #[test]
    fn test_parse_vla_1_simulcast_stream_with_no_active_layers() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0100_0000,
                // 1 bitmask
                0b0000_0000,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 1,
                simulcast_streams: vec![SimulcastStreamAllocation {
                    spatial_layers: vec![],
                }],
            })
        );
    }

    #[test]
    fn test_parse_vla_3_simulcast_streams_with_no_active_layers() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0110_0000,
                // 3 active spatial layer bitmasks, 4 bits each
                0b0000_0000,
                0b0000_1111,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 1,
                simulcast_streams: vec![
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    }
                ],
            })
        );
    }

    #[test]
    fn test_parse_vla_3_simulcast_streams_with_1_active_spatial_layers_and_2_temporal_layers() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0110_0001,
                // 3 temporal layer counts (minus 1), 2 bits each
                0b0101_0100,
                // 6 temporal layer bitrates
                0b0000_0001,
                0b0000_0010,
                0b0000_0100,
                0b0000_1000,
                0b0001_0000,
                0b0010_0000,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 1,
                simulcast_streams: vec![
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation { cumulative_kbps: 1 },
                                TemporalLayerAllocation { cumulative_kbps: 2 }
                            ],
                            resolution_and_framerate: None,
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation { cumulative_kbps: 4 },
                                TemporalLayerAllocation { cumulative_kbps: 8 }
                            ],
                            resolution_and_framerate: None,
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 16
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 32
                                }
                            ],
                            resolution_and_framerate: None,
                        }],
                    }
                ],
            })
        );
    }

    #[test]
    fn test_parse_vla_3_simulcast_streams_with_1_active_spatial_layers_and_2_temporal_layers_with_resolutions(
    ) {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0110_0001,
                // 3 temporal layer counts (minus 1), 2 bits each
                0b0101_0100,
                // 6 temporal layer bitrates
                100,
                101,
                110,
                111,
                120,
                121,
                // 3 resolutions + framerates (5 bytes each)
                // 320x180x15
                1,
                63,
                0,
                179,
                15,
                // 640x360x30
                2,
                127,
                1,
                103,
                30,
                // 1280x720x60
                4,
                255,
                2,
                207,
                60,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 1,
                simulcast_streams: vec![
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 100
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 101
                                }
                            ],
                            resolution_and_framerate: Some(ResolutionAndFramerate {
                                width: 320,
                                height: 180,
                                framerate: 15,
                            }),
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 110
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 111
                                }
                            ],
                            resolution_and_framerate: Some(ResolutionAndFramerate {
                                width: 640,
                                height: 360,
                                framerate: 30,
                            }),
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 120
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 121
                                }
                            ],
                            resolution_and_framerate: Some(ResolutionAndFramerate {
                                width: 1280,
                                height: 720,
                                framerate: 60,
                            }),
                        }],
                    }
                ],
            })
        );
    }

    #[test]
    fn test_parse_vla_3_simulcast_streams_with_differing_active_spatial_layers_with_resolutions() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0010_0000,
                // 3 active spatial layer bitmasks, 4 bits each; only the base layer is active
                0b0001_0000,
                0b0000_1111,
                // 1 temporal layer counts (minus 1), 2 bits each
                0b0100_0000,
                // 2 temporal layer bitrates
                100,
                101,
                // 1 resolutions + framerates (5 bytes)
                // 320x180x15
                1,
                63,
                0,
                179,
                15,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 100
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 101
                                }
                            ],
                            resolution_and_framerate: Some(ResolutionAndFramerate {
                                width: 320,
                                height: 180,
                                framerate: 15,
                            }),
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    }
                ],
            })
        );
    }

    #[test]
    fn test_parse_vla_1_simulcast_streams_with_3_spatial_layers() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0000_0111,
                // 3 temporal layer counts (minus 1), 2 bits each
                0b0101_0100,
                // 6 temporal layer bitrates
                100,
                101,
                110,
                111,
                120,
                121,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![SimulcastStreamAllocation {
                    spatial_layers: vec![
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 100
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 101
                                }
                            ],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 110
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 111
                                }
                            ],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 120
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 121
                                }
                            ],
                            resolution_and_framerate: None,
                        }
                    ],
                },],
            })
        );
    }

    #[test]
    fn test_parse_vla_1_simulcast_streams_with_4_spatial_layers_1_inactive() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0000_1011,
                // 3 temporal layer counts (minus 1), 2 bits each
                0b0101_0100,
                // 6 temporal layer bitrates
                100,
                101,
                110,
                111,
                120,
                121,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![SimulcastStreamAllocation {
                    spatial_layers: vec![
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 100
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 101
                                }
                            ],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 110
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 111
                                }
                            ],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 120
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 121
                                }
                            ],
                            resolution_and_framerate: None,
                        }
                    ],
                },],
            })
        );
    }
}
