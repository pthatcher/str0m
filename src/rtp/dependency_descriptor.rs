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

pub struct DependencyDescriptor2 {
    // Bits 0..2 of byte 0
    first_packet_in_frame: bool,
    last_packet_in_frame: bool,

    // Bits 2..8 of byte 0 (not really part of the data model)
    frame_dependency_template_id_: u8,

    // Bytes 1..3
    frame_number: u16,

    // (optional if more than 3 bytes)
    // Bit 0 of byte 3 (not really part of the data model; descriptor.attached_structure.is_some())
    template_dependency_structure_present: bool,
    // Bit 1 of byte 3 (not really part of the data model)
    active_decode_targets_present: bool,
    // Bit 2 of byte 3 (not really part of the data model)
    custom_dtis: bool,
    // Bit 3 of byte 3 (not really part of the data model)
    custom_fdiffs: bool,
    // Bit 4 of byte 3 (not really part of the data model)
    custom_chains: bool,
    // Bit 5 of byte 3 (not really part of the data model)
    custom_chains: bool,
    // (optional if template_dependency_structure_present)
    // Bits 0..6 of bytes X..
    structure_id: u8,
    // Bits 6..13 of bytes X..
    

    resolution: Option<Resolution>,

    FrameDependencyTemplate frame_dependencies;
    absl::optional<uint32_t> active_decode_targets_bitmask;
    std::unique_ptr<FrameDependencyStructure> attached_structure;
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_dependency_descriptor_empty_buffer() {
        assert_eq!(DepdendencyDescriptor::parse(&[]), None);
    }
}
