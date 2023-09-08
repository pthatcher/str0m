use super::{ExtensionSerializer, ExtensionValues};

#[allow(dead_code)]
/// URI for the Depdendency Descriptor RTP Header Extension
pub const URI: &str =
    "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension";

/// Top-level "descriptor" of dependencies for the Depdendency Descriptor RTP Header Extension
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DepdendencyDescriptor {
    raw: Vec<u8>,
}

impl DepdendencyDescriptor {
    #[allow(dead_code)]
    fn parse(buf: &[u8]) -> Option<Self> {
        Some(Self { raw: buf.to_vec() })
    }
}
/// Serializer of the Dependency Descriptor RTP Header Extension
#[derive(Debug)]
pub struct Serializer;

impl ExtensionSerializer for Serializer {
    fn needs_two_byte_header(&self, ev: &ExtensionValues) -> bool {
        let Some(dd) = ev.user_values.get::<DepdendencyDescriptor>() else {
            return false;
        };
        dd.raw.len() > 16
    }

    fn write_to(&self, buf: &mut [u8], ev: &ExtensionValues) -> usize {
        let Some(dd) = ev.user_values.get::<DepdendencyDescriptor>() else {
            return 0;
        };
        let len = dd.raw.len();
        if buf.len() < len {
            return 0;
        }
        buf[..len].copy_from_slice(&dd.raw);
        len
    }

    fn parse_value(&self, buf: &[u8], ev: &mut ExtensionValues) -> bool {
        let Some(dd) = DepdendencyDescriptor::parse(buf) else {
            return false;
        };
        ev.user_values.set(dd);
        true
    }

    fn is_video(&self) -> bool {
        true
    }

    fn is_audio(&self) -> bool {
        false
    }
}

