use super::{ExtensionSerializer, ExtensionValues};

#[allow(dead_code)]
/// URI for the Dependency Descriptor RTP Header Extension
pub const URI: &str =
    "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension";

// Here is a summary of the spec which might be easier to read.
//
// Definitions
//  - Frame
//    - Is an encoded video frame with metadata
//    - Is identified by a frame_number
//    - May share a timestamp with other Frames when there is more than one spatial layer.
//  - Referred Frame
//    - Is a Frame on which another Frame depends.  In other words, a dependency.
//    - May be among many dependencies of a Frame.  A Frame is decodable if all of its Referred Frames are decodable.
//  - Decode Target
//    - Is a subset of Frames necessary to decode at a certain fidelity (spatial layer, temporal layer)
//    - Different Decode Targets may share Frames (a frame may be in several Decode Targets).
//    - Typically, a Selective Forwarding Middlebox (SFM) will forward one Decode Target at a time (to a given decoder).
//  - Active Decode Targets
//    - The subset of Decode Targets actively produced by an encoder or fowarded by a Selective Forwarding Middlebox (SFM).
//    - Other Decode Targets are not actively being produced or forwarded.
//    - Updates must be resilient to packet loss, either by resending the current value
//      until a packet with the latest value is acknowledged, or by sending a new keyframe when the value changes.
//  - Decode Target Indication (DTI)
//    - Describes the relationship of a frame to a Decode Target
//      - Not Present
//        - The frame is not in the Decode Target
//        - An SFM forwarding the Decode Target should not forward the frame.
//      - Switch
//        - The frame is in the Decode Target
//        - All subsequent frames in the Decode Target will be decodable if the frame is decodable.
//        - An SFM may beging forwarding the Decode Target at this frame.
//      - Required:
//        - The frame is in the Decode Target
//        - An SFM forwarding the Decode Target should forward the frame; failing to do so would make subsequent frames undecodable.
//      - Discardable
//        - The frame is in the Decode Target
//        - An SFM forwarding the Decode Target should forward the frame, but failing to do so would not make subsequent frames undecodable.
//  - Chain or Chain Information
//    - Indicates if any missed packets are required for the Decode Target to remain decodable.
//    - Is a generalization of the TL0PICIDX field used in the RTP payload formats for scalable codecs such as VP8 and VP9.
//    - Is a sequence of frames for which it can be determined instantly if a frame from that sequence has been lost.
//    - Is a sequence of frames essential to decode Decode Targets protected by that Chain
//    - Every packet includes, for every Chain, the frame_number of the previous frame in that Chain.
//    - The Chain is intact as long as every frame in the Chain is received, otherwise it is broken.
//    - A receiver, having received all frames in a Chain, and having missed one or more frames not in the Chain,
//      need not request additional information (e.g., NACK or FIR) from the sender in order to resume decoding
//      at the fidelity of the Decode Target protected by the Chain.
//    - A frame that is not present in the Chain may be dropped
//      even if the Decode Target Indication for that frame is not Discardable.
//    - Chains protecting no active Decode Targets MUST be ignored.
//    - To increase the chance of using a predefined template, chains protecting no active Decode targets
//      may refer to any frame, including a frame that was never produced.
//    - Due to the fact that the Chain information is present in all packets,
//      an SFM can detect a broken Chain regardless of whether
//      the first packet received after a loss is part of that Chain or not.
//    - When Chains are used, an SFM MAY switch to a Decode Target at any point
//      if the Chain tracking that Decode Target is intact.
//        - When Chains are used, an SFM may "switch" to the Decode target at any point
//          if the Chain protecting that Decode Target is intact.
//  - Frame Dependency Structure
//    - Avoids sending repetitive information by referring to previously sent information shared between many frames.
//    - Contains the number of Decode Targets, Frame Depdencey Templates, and a mapping between Chains and Decode Targets.
//  - Frame Dependency Template
//    - Part of a Frame Dependency Structure
//    - Contains spatial layer ID, temporal layer ID, Referred Frames, Decode Target Indications, and Change Information.
//
// Information available in each desciptor value, either explicitly or by referencing a Frame Dependency Template:
//  - frame_number
//  - Spatial Layer ID
//  - Temporal Layer ID
//  - Decoded Target Indications
//  - Referred Frames
//  - The previous frame in each Chain
//
// Header extension format:
//  f(n) = n bits of big-endian uint
//  ns(n) = a variable-length int that can encode 0..n-1.
//          It's either log2(n) or log2(n)-1 bits.
//          It can save a bit for small values by using the "wasted" possible values for log2(n) bits in a clever way.
//  dependency_descriptor(extended)
//   mandatory_fields
//    f(1) start_of_frame
//    f(1) end_of_frame
//    f(6) frame_dependency_template_id
//    f(16) frame_number
//  if extended
//   extended_fields()
//    f(1) template_dependency_structure_present_flag
//    f(1) active_decode_targets_present_flag
//    f(1) custom_dtis_flag
//    f(1) custom_fdiffs_flag
//    f(1) custom_chains_flag
//    if template_dependency_structure_present_flag
//     template_dependency_structure()
//      f(6) template_id_offset
//      f(5) dt_cnt_minus_one  // When parsing, this is how you learn decode_target_count
//      template_layers()
//       template_count Times
//        f(2) next_layer_idc  // When parsing, this is how you learn the number of spatial and temporal layers
//       f(2) 3 // terminal value.  When parsing, this is how you learn template_count
//      template_dtis()
//       template_count times
//        decode_target_count times
//         f(2) dti
//      template_fdiffs()
//       template_count times
//        fdiff_count times
//         f(1) 1
//         f(4) fdiff_minus_one
//        f(1) 0  // terminal value.  When parsing, this is how you learn fdiff_count
//      template_chains()
//       ns(decode_target_count + 1) chain_count
//       if chain_count > 0
//        decode_target_count times
//         ns(chain_count) decode_target_protected_by
//        template_count times
//         chain_count times
//          f(4) template_chain_fdiff
//      1 resolutions_present_flag
//      if resolutions_present_flag
//       render_resolutions()
//        spatial_layer_count times
//         f(16) max_render_width_minus_1
//         f(16) max_render_height_minus_1
//     if active_decode_targets_present_flag
//    f(decode_target_count) active_decode_targets_bitmask
//  frame_dependency_definition()
//   if custom_dtis_flag
//    frame_dtis()
//     decode_target_count times
//      f(2) frame_dti
//   if custom_fdiffs_flag
//    frame_fdiffs()
//     template_count times
//      fdiff_count times
//       f(2) fdiff_size
//       f(4*fdiff_size) fdiff_minus_one
//      f(2) 0  // terminal value.  When parsing, this is how you learn fdiff_count
//   if custom_chains_flag
//    frame_chains()
//     chain_count times
//      f(8) frame_chain_fdiff
//  0-7 bits of zero_padding
//

/// Top-level "descriptor" of dependencies for the Dependency Descriptor RTP Header Extension
/// in it unparsed form.  This is useful when forwarding as-is (without parsing and then
/// serializing back to exactly what it was).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnparsedSerializedDescriptor(Vec<u8>);

impl UnparsedSerializedDescriptor {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parse the serialized Dependency Descriptor.
    /// This requires a cached value of the "shared structure" and the "active decode targets bitmask".
    /// Those values are provided in the return value as ParsedDependencyDescriptor::updated_shared_structure
    /// and ParsedDependencyDescriptor::udpated_active_decode_targets_bitmask.
    /// They are None when unchanged and Some when changed.
    /// The caller must cache the latest non-None values and pass them back subsequent calls to Parse.
    /// Note: This caching must take packet reordering into account and only cache the
    /// value from the latest packet.
    pub fn parse(
        &self,
        latest_shared_structure: Option<&SharedStructure>,
        latest_active_decode_targets_bitmask: Option<u32>,
    ) -> ParseResult<ParsedDependencyDescriptor> {
        let mut parser = Parser {
            bit_stream: BitStream::new(self.as_bytes()),
        };
        parser.dependency_descriptor(
            latest_shared_structure,
            latest_active_decode_targets_bitmask,
        )
    }
}

/// Identifies a video frame
/// Wraps upon reaching the maximum value, so should be expanded.
/// The spec calls it "frame_number"
pub type TruncatedFrameNumber = u16;
/// The difference between one frame number and another
/// The spec calls it "fdiff"
pub type RelativeFrameNumber = u16;
/// Identifies a spatial layer.
/// The spec calls it "SpatialID"
/// The spec doesn't seen to limit the range, but a realistic range is 0..=3
// but libwebrtc limits it to 0-3.
pub type SpatialLayerId = u8;
/// Identifies a temporal layer.
/// The spec calls it "TemporalID"
/// Realistic range is 0..=3.
/// The spec doesn't seen to limit the range, but a realistic range is 0..=3
// but libwebrtc limits it to 0-3.
pub type TemporalLayerId = u8;
/// Identifies a "chain"
/// Range is 0..=31.
pub type ChainIndex = u8;

/// Top-level "descriptor" of dependencies for the Dependency Descriptor RTP Header Extension
/// in it parsed form.  Call SerializeDependencyDescriptor::parse to parse the serialized form.
#[derive(Debug)]
pub struct ParsedDependencyDescriptor {
    /// Identifies the current frame.
    /// Monotonically increases strictly in decode order.
    /// All packets of the same frame have the same frame number.
    /// The spec calls it "frame_number"
    pub truncated_frame_number: TruncatedFrameNumber,

    /// Identifies the spatial layer of the current frame.
    /// The spec calls it FrameSpatialId or spatial_id.
    pub spatial_layer_id: SpatialLayerId,

    /// Identifies the temporal layer of the current frame.
    /// The spec calls it FrameTemporalId or temporal_id.
    pub temporal_layer_id: TemporalLayerId,

    /// Maximum render width and height of the current frame, if known.
    /// The spec calls it FrameMaxWidth or max_render_width and FrameMaxHeight or max_render_height.
    pub resolution: Option<Resolution>,

    /// The relative frame numbers of the frames the current frame depends on.
    /// For AV1, referred frames must have a spatial_layer_id less than or equal to the spatial_layer_id of the current frame,
    /// and a temporal_layer_id less than or equal to the temporal_layer_id of the current frame.
    /// The current frame must be decodable if all of the referred frames are decodable.
    /// The spec calls it "fdiff" or "FrameFdiff"
    pub referred_relative_frame_numbers: Vec<RelativeFrameNumber>,

    /// For all Chains, the relative frame number of the previous frame in the Chain.
    /// As long as every frame in the Chain is received, the frames of any
    /// Decode Target protected by the Chain will be decodable.
    /// The spec calls it "frame_chain_fdiff" or
    pub previous_relative_frame_number_by_chain_index: Vec<RelativeFrameNumber>,

    /// True if and only if this is the first packet of the current frame.
    /// The spec calls it "start_of_frame"
    pub is_first_packet: bool,

    /// True if and only if this is the last packet of the current frame.
    /// The spec calls it "end_of_frame"
    pub is_last_packet: bool,

    /// Information about all the Decode Targets and how the current frame relates to them.
    pub decode_targets: Vec<DecodeTarget>,

    /// If non-None, the latest value must be cached and passed back into Parse so that future
    /// parsing may depend on previous structures/templates.
    /// Note: This caching must take packet reordering into account and only cache the
    /// value from the latest packet.
    pub updated_shared_structure: Option<SharedStructure>,

    /// If non-None, the latest value must be cached and passed back into Parse so that future
    /// parsing may depend on previous bitmask values.
    /// Note: This caching must take packet reordering into account and only cache the
    /// value from the latest packet.
    pub udpated_active_decode_targets_bitmask: Option<u32>,
}

/// The max render width and height, typically of a spatial layer.
#[derive(Clone, Debug)]
pub struct Resolution {
    /// Maximum render width
    /// Range: 1..=65536
    /// The spec says "max_render_height_minus_1[spatial_id]: indicates the maximum render height
    ///   minus 1 for frames with spatial ID equal to spatial_id."
    pub max_render_width: u32,
    /// Maximum render height
    /// Range: 1..=65536
    /// The spec says: "max_render_width_minus_1[spatial_id]: indicates the maximum render width
    ///   minus 1 for frames with spatial ID equal to spatial_id."
    pub max_render_height: u32,
}

/// The subset of video frames necessary to decode a particular combination of temporal layer and spatial layer (spatial_layer_id, temporal_layer_id).
/// Every video frame has a relationship with a Decode Target, called a Decode Target Indication.
/// Each Decode Target can be protected a Chain.
#[derive(Debug)]
pub struct DecodeTarget {
    /// Identifies the spatial layer of the Decode Target.
    pub spatial_layer_id: SpatialLayerId,

    /// Identifies the temporal layer of the Decode Target.
    pub temporal_layer_id: TemporalLayerId,

    /// If the Decode Target is being sent.
    pub active: bool,

    /// How the frame relates to the Decode Target
    pub indication: DecodeTargetIndication,

    /// If the Decode Target is protected by a Chain, this is the index of that Chain.
    // libwebrtc calls it "decode_target_protected_by_chain"
    pub protecting_chain_index: Option<ChainIndex>,
}

/// The relationship a video frame has to a Video Decode Target.
#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Copy, Debug)]
pub enum DecodeTargetIndication {
    /// The current frame is not part of the Decode Target.
    /// So, a Selective Forwarding Middlebox (SFM) should not forward
    /// this frame when forwarding the frames of the Decode Target.
    NotPresent = 0,
    /// The current frame is part of the Decode Target, but no subsequent
    /// frames of the Decode Target will depend on the current frame.
    /// So, a Selective Forwarding Middlebox (SFM) should forward this frame
    /// if it is known to be decodable.  But if it discards it,
    /// subsequent frames of the Decode Target will still be decodable.
    Discardable = 1,
    /// The current frame is part of the Decode Target, and subsequent
    /// frames of the Decode Target, and all subsequent frames for the
    /// Decode Target will be decodable if the current frame is decodable.
    /// So, a Selective Forwarding Middlebox (SFM) may forward this frame
    /// if it is known to be decodable, and then begin forwarding frames
    /// of the Decode Target.
    Switch = 2,
    /// The current frame is part of the Decode Target, and subsequent
    /// frames of the Decode Target may depend on the current frame,
    /// but subsequent frames may not be decodable just because the
    /// current frame is decodable.
    /// So, a Selective Forwarding Middlebox (SFM) must forward this frame
    /// to keep the Decode Target decodable, but can not "switch"
    /// to the Decode Target at the current frame.
    Required = 3,
}

impl DecodeTargetIndication {
    fn from_u2(u2: u8) -> Option<DecodeTargetIndication> {
        Some(match u2 {
            0 => DecodeTargetIndication::NotPresent,
            1 => DecodeTargetIndication::Discardable,
            2 => DecodeTargetIndication::Switch,
            3 => DecodeTargetIndication::Required,
            _ => {
                return None;
            }
        })
    }
}

/// Depdendency information shared between many frames.
/// Caching it allows saving bytes on the wire by avoiding sending duplicate information.
/// The spec calls it "Frame Dependency Structure" or "Template Dependency Structure"
// libwebrtc calls it "FrameDependencyStructure"
// %%% call it just Structure?
#[derive(Debug)]
pub struct SharedStructure {
    /// The number of Decode Targets
    /// Range: 1..=32
    /// The spec calls it "DtCnt"
    // libwebrtc calls it "num_decode_targets"
    pub decode_target_count: u8,

    /// The number of Chains.
    /// Range: 0..=32
    /// The spec says "chain_cnt: indicates the number of Chains.
    ///   When set to zero, the Frame dependency structure does not utilize protection with Chains."
    // libwebrtc calls it "num_chains"
    pub chain_count: u8,

    /// For each Decode Target, the index of the Chain protecting it
    pub protecting_chain_index_by_decode_target_index: Vec<ChainIndex>,

    /// For each spatial layer, its resolution, if known.
    /// None if unknown.
    // libwebrtc calls it "resolutions"
    pub resolution_by_spatial_id: Option<Vec<Resolution>>,

    /// Templates indexed by (template_id - template_id_offset) % 64
    /// In other words, if there were a template_by_id, then template_by_id_minus_offset[0] == template_by_id[template_id_offset]
    /// If you want to get template_by_id[template_id], then get template_by_id_minux_offset[template_id - template_id_offset]
    /// This is a combination of what spec calls
    ///   "TemplateSpatialId", "TemplateTemporalId", "template_dti", "TemplateFdiff", "template_chain_fdiff"
    // libwebrtc calls it "templates"
    pub template_by_id_minus_offset: Vec<SharedStructureTemplate>,

    /// The index into template_by_id_minus_offset is (template_id - template_id_offset)
    pub template_id_offset: u8,
}

/// A template that a frame can reference.  Using these saves bytes over the wire.
/// The spec calls it "Frame Dependency Template".
// libwebrtc calls it "FrameDependencyTemplate".
// %%% call it just Template?
#[derive(Clone, Debug)]
pub struct SharedStructureTemplate {
    /// Identifies the spatial layer of the frame referencing this template.
    /// The spec calls it "TemplateSpatialId".
    pub spatial_layer_id: SpatialLayerId,

    /// Identifies the temporal layer of the frame referencing this template.
    /// The spec calls it "TemplateTemporalId".
    pub temporal_layer_id: TemporalLayerId,

    /// Indicates the relationships (Decode Target Indications) of the frame referencing this template
    /// to all Decode Targets.
    /// The spec calls them "template_dti"
    // libwebrtc calls them "decode_target_indications"
    pub decode_target_indication_by_decode_target_index: Vec<DecodeTargetIndication>,

    /// Indicates the dependencies of the frame referencing this template to other frames,
    /// by the difference between the referred frame's number and the current frame's number.
    /// Range of each diff: 1..=16
    /// The spec calls them "TemplateFdiff".
    // libwebrtc: "frame_diffs"
    pub referred_relative_frame_numbers: Vec<RelativeFrameNumber>,

    /// For each Chain, the previous frame in the Chain, relative to the frame
    /// referencing this template.
    /// Range of each diff: 0..=15
    /// The spec calls them "template_chain_fdiff"
    // libwebrtc call them "chain_diffs"
    pub previous_relative_frame_number_by_chain_index: Vec<RelativeFrameNumber>,
}

impl SharedStructure {
    /// The layer IDs (spatial, temporal) of each Decode Target
    /// The spec calls this method "decode_target_layers()"
    /// and the values "DecodeTargetSpatialId" and "DecodeTargetTemporalId"
    pub fn layer_ids_by_decode_target_index(&self) -> Vec<(SpatialLayerId, TemporalLayerId)> {
        let mut layer_ids_by_decode_target_index =
            Vec::with_capacity(self.decode_target_count as usize);
        // The spec call this "dtIndex".
        for decode_target_index in 0..self.decode_target_count {
            let mut spatial_layer_id = 0;
            let mut temporal_layer_id = 0;
            for template in &self.template_by_id_minus_offset {
                if let Some(&dti) = template
                    .decode_target_indication_by_decode_target_index
                    .get(decode_target_index as usize)
                {
                    if dti != DecodeTargetIndication::NotPresent {
                        spatial_layer_id = spatial_layer_id.max(template.spatial_layer_id);
                        temporal_layer_id = temporal_layer_id.max(template.temporal_layer_id);
                    }
                }
            }
            layer_ids_by_decode_target_index.push((spatial_layer_id, temporal_layer_id));
        }
        layer_ids_by_decode_target_index
    }
}

/// Serializer of the Dependency Descriptor RTP Header Extension
#[derive(Debug)]
pub struct Serializer;

impl ExtensionSerializer for Serializer {
    fn write_to(&self, buf: &mut [u8], ev: &ExtensionValues) -> usize {
        let Some(unparsed) = ev.user_values.get::<UnparsedSerializedDescriptor>() else {
            return 0;
        };
        let len = unparsed.as_bytes().len();
        if buf.len() < len {
            return 0;
        }
        buf[..len].copy_from_slice(unparsed.as_bytes());
        len
    }

    fn parse_value(&self, buf: &[u8], ev: &mut ExtensionValues) -> bool {
        let unparsed = UnparsedSerializedDescriptor(buf.to_vec());
        ev.user_values.set(unparsed);
        true
    }

    fn is_video(&self) -> bool {
        true
    }

    fn is_audio(&self) -> bool {
        false
    }

    fn requires_two_byte_form(&self, ev: &ExtensionValues) -> bool {
        let Some(unparsed) = ev.user_values.get::<UnparsedSerializedDescriptor>() else {
            return false;
        };
        unparsed.as_bytes().len() > 16
    }
}

/// The things that can go wrong when parsing the Dependency Descriptor
#[derive(Debug)]
pub enum ParseError {
    /// The buffer being read doesn't have enough bits.
    NotEnoughBits,
    /// The shared structure isn't known, which means that either it wasn't included in the header extension
    /// when it should have been, or the latest value isn't being cached correctly.
    UnknownSharedStructure,
    /// The latest active decode target bitmask isn't known,
    /// which means that either it wasn't included in the header extension
    /// when it should have been, or the latest value isn't being cached correctly.
    UnknownActiveDecodeTargetBitmask,
    /// The template layer ID provided isn't valid for the latest shared structure,
    /// which means that either the serialized value is invalid or the shared structure isn't being cached correctly.
    InvalidTemplateId,
    /// The spatial layer ID is too large.
    InvalidSpatialLayerId,
    /// The temporal layer ID is too large.
    InvalidTemporalLayerId,
}

type ParseResult<T> = Result<T, ParseError>;

struct Parser<'bits> {
    bit_stream: BitStream<'bits>,
}

impl<'bits> Parser<'bits> {
    // This is made to match the method called "dependency_descriptor()" in the spec.
    fn dependency_descriptor(
        &mut self,
        latest_shared_structure: Option<&SharedStructure>,
        latest_active_decode_targets_bitmask: Option<u32>,
    ) -> ParseResult<ParsedDependencyDescriptor> {
        let mandatory_fields = self.mandatory_descriptor_fields()?;
        let (custom_flags, extended_fields) = if !self.is_empty() {
            self.extended_descriptor_fields()?
        } else {
            self.no_extended_descriptor_fields()
        };
        let Some(shared_structure) = extended_fields.as_ref().and_then(|ef| ef.shared_structure.as_ref()).or(latest_shared_structure) else {
            return Err(ParseError::UnknownSharedStructure)
        };
        let Some(active_decode_targets_bitmask) = extended_fields.as_ref().and_then(|ef| ef.active_decode_targets_bitmask).or(latest_active_decode_targets_bitmask) else {
            return Err(ParseError::UnknownActiveDecodeTargetBitmask)
        };
        let frame_dependency_definition = self.frame_dependency_definition(
            shared_structure,
            mandatory_fields.template_id,
            custom_flags,
        )?;
        // The spec says "zero_padding: MUST be set to 0 and be ignored by receivers"

        // The spec calls this "decode_target_layers"
        let layer_ids_by_decode_target_index = shared_structure.layer_ids_by_decode_target_index();
        let decode_targets: Vec<DecodeTarget> = layer_ids_by_decode_target_index
            .into_iter()
            .enumerate()
            .map(
                |(decode_target_index, (spatial_layer_id, temporal_layer_id))| {
                    let active = BitStream::read_ls_bit_of_u32(
                        active_decode_targets_bitmask,
                        decode_target_index as u8,
                    )
                    .unwrap_or(false);
                    let indication = frame_dependency_definition
                        .decode_target_indication_by_decode_target_index
                        .get(decode_target_index)
                        .copied()
                        .unwrap_or(DecodeTargetIndication::NotPresent);
                    let protecting_chain_index = shared_structure
                        .protecting_chain_index_by_decode_target_index
                        .get(decode_target_index)
                        .copied();
                    DecodeTarget {
                        spatial_layer_id,
                        temporal_layer_id,
                        active,
                        indication,
                        protecting_chain_index,
                    }
                },
            )
            .collect();
        Ok(ParsedDependencyDescriptor {
            truncated_frame_number: mandatory_fields.frame_number,
            spatial_layer_id: frame_dependency_definition.spatial_layer_id,
            temporal_layer_id: frame_dependency_definition.temporal_layer_id,
            resolution: frame_dependency_definition.resolution,
            referred_relative_frame_numbers: frame_dependency_definition
                .referred_relative_frame_numbers,
            previous_relative_frame_number_by_chain_index: frame_dependency_definition
                .previous_relative_frame_number_by_chain_index,
            is_first_packet: mandatory_fields.start_of_frame,
            is_last_packet: mandatory_fields.end_of_frame,
            decode_targets,
            udpated_active_decode_targets_bitmask: extended_fields
                .as_ref()
                .and_then(|ef| ef.active_decode_targets_bitmask),
            updated_shared_structure: extended_fields.and_then(|ef| ef.shared_structure),
        })
    }

    // This is made to match the method called "mandatory_descriptor_fields()" in the spec.
    fn mandatory_descriptor_fields(&mut self) -> ParseResult<MandatoryFields> {
        // The spec says "MUST be set to 1 if the first payload byte of the RTP packet is the beginning of a new frame,
        //   and MUST be set to 0 otherwise. Note that this frame might not be the first frame of a temporal unit."
        // libwebrtc calls it "first_packet_in_frame"
        let start_of_frame = self.f1()?;
        // The spec says "MUST be set to 1 for the final RTP packet of a frame, and MUST be set to 0 otherwise.
        //   Note that, if spatial scalability is in use, more frames from the same temporal unit may follow."
        // libwebrtc calls it "last_packet_in_frame"
        let end_of_frame = self.f1()?;
        // The spec says "frame_dependency_template_id is the ID of the Frame dependency template to use.
        //   MUST be in the range of template_id_offset to (template_id_offset + TemplateCnt - 1), inclusive.
        //   frame_dependency_template_id MUST be the same for all packets of the same frame."
        // Range: 0..=63
        let template_id = self.f(6)? as u8;
        // The spec says "is represented using 16 bits and increases strictly monotonically in decode order.
        //  frame_number MAY start on a random number, and MUST wrap after reaching the maximum value.
        //  All packets of the same frame MUST have the same frame_number value.
        //  Note: frame_number is not the same as Frame ID in AV1 specification."
        let frame_number = self.f(16)? as u16;
        Ok(MandatoryFields {
            start_of_frame,
            end_of_frame,
            template_id,
            frame_number,
        })
    }

    // This is made to match the method called "extended_descriptor_fields()" in the spec.
    fn extended_descriptor_fields(&mut self) -> ParseResult<(CustomFlags, Option<ExtendedFields>)> {
        // The spec says "indicates the presence the template_dependency_structure.
        //   When the template_dependency_structure_present_flag is set to 1,
        //   template_dependency_structure MUST be present;
        //   otherwise template_dependency_structure MUST NOT be present.
        //   template_dependency_structure_present_flag MUST be set to 1
        //   for the first packet of a coded video sequence, and MUST be set to 0 otherwise."
        let template_dependency_structure_present_flag = self.f1()?;
        // The spec says "indicates the presence of active_decode_targets_bitmask.
        //   When set to 1, active_decode_targets_bitmask MUST be present,
        //   otherwise, active_decode_targets_bitmask MUST NOT be present."
        let active_decode_targets_present_flag = self.f1()?;
        // The spec says "indicates the presence of frame_dtis.
        //   When set to 1, frame_dtis MUST be present.
        //   Otherwise, frame_dtis MUST NOT be present."
        let custom_dtis_flag = self.f1()?;
        // The spec says "indicates the presence of frame_fdiffs.
        //   When set to 1, frame_fdiffs MUST be present.
        //   Otherwise, frame_fdiffs MUST NOT be present."
        let custom_fdiffs_flag = self.f1()?;
        // The spec says "indicates the presence of frame_chain_fdiff.
        //   When set to 1, frame_chain_fdiff MUST be present.
        //   Otherwise, frame_chain_fdiff MUST NOT be present."
        let custom_chains_flag = self.f1()?;
        // The spec says "contains a bitmask that indicates which Decode targets are available for decoding.
        //   Bit i is equal to 1 if Decode target i is available for decoding, 0 otherwise.
        //   The least significant bit corresponds to Decode target 0."
        // The spec calls this "template_dependency_structure"
        // %%% rename shared_stucture here?
        let mut shared_structure = None;
        let mut active_decode_targets_bitmask = None;
        if template_dependency_structure_present_flag {
            let template_dependency_structure = self.template_dependency_structure()?;
            // The spec calls this "DtCnt".
            // Range: 1..=32
            let decode_target_count = template_dependency_structure.decode_target_count;
            shared_structure = Some(template_dependency_structure);
            // If decode_target_count is 32, need 33 bits temporarily
            active_decode_targets_bitmask = Some(((1u64 << decode_target_count) - 1) as u32);
        }
        if active_decode_targets_present_flag {
            if let Some(shared_structure) = &shared_structure {
                // The spec calls this "DtCnt".
                // Range: 1..=32
                let decode_target_count = shared_structure.decode_target_count;
                active_decode_targets_bitmask = Some(self.f(decode_target_count)?);
            }
        }
        let custom_frame_dependency_flags = CustomFlags {
            chains: custom_chains_flag,
            dtis: custom_dtis_flag,
            fdiffs: custom_fdiffs_flag,
        };
        let extended_descriptor_fields = Some(ExtendedFields {
            shared_structure,
            active_decode_targets_bitmask,
        });
        Ok((custom_frame_dependency_flags, extended_descriptor_fields))
    }

    // This is made to match the method called "no_extended_descriptor_fields()" in the spec.
    fn no_extended_descriptor_fields(&self) -> (CustomFlags, Option<ExtendedFields>) {
        let custom_frame_dependency_flags = CustomFlags {
            chains: false,
            dtis: false,
            fdiffs: false,
        };
        let extended_descriptor_fields = None;
        (custom_frame_dependency_flags, extended_descriptor_fields)
    }

    // This is made to match the method called "template_dependency_structure()" in the spec.
    fn template_dependency_structure(&mut self) -> ParseResult<SharedStructure> {
        // The spec says "indicates the value of the frame_dependency_template_id having templateIndex=0.
        //   The value of template_id_offset SHOULD be chosen so that the valid frame_dependency_template_id range,
        //   template_id_offset to template_id_offset + TemplateCnt - 1, inclusive,
        //   of a new template_dependency_structure, does not overlap the valid frame_dependency_template_id range
        //   for the existing template_dependency_structure.
        //   When template_id_offset of a new template_dependency_structure is the same as in the existing
        //   template_dependency_structure, all fields in both template_dependency_structures MUST have identical values."
        // libwebrtc calls it "structure_id"
        // Range: 0..=63
        let template_id_offset = self.f(6)? as u8;
        // The spec says "dt_cnt_minus_one + 1 indicates the number of Decode targets present in the coded video sequence."
        // Range: 0..=31
        let dt_cnt_minus_one = self.f(5)? as u8;
        // The spec calls this "DtCnt".
        // Range: 1..=32
        let decode_target_count = dt_cnt_minus_one + 1;
        let mut template_by_id_minus_offset = self.template_layers(decode_target_count)?;
        self.template_dtis(&mut template_by_id_minus_offset, decode_target_count)?;
        self.template_fdiffs(&mut template_by_id_minus_offset)?;
        let (chain_count, protecting_chain_index_by_decode_target_index) =
            self.template_chains(&mut template_by_id_minus_offset, decode_target_count)?;
        // The spec calculates and stores "decode_target_layers" here, but we derive it on demand as SharedStructure::layer_ids_by_decode_target_index.
        // The spec says "indicates the presence of render_resolutions.
        //   When the resolutions_present_flag is set to 1, render_resolutions MUST be present;
        //   otherwise render_resolutions MUST NOT be present."
        let resolutions_present_flag = self.f1()?;
        let resolution_by_spatial_id = if resolutions_present_flag {
            if let Some(max_spatial_id) = template_by_id_minus_offset
                .iter()
                .map(|template| template.spatial_layer_id)
                .max()
            {
                Some(self.render_resolutions(max_spatial_id)?)
            } else {
                Some(vec![])
            }
        } else {
            None
        };
        Ok(SharedStructure {
            decode_target_count,
            chain_count,
            protecting_chain_index_by_decode_target_index,
            resolution_by_spatial_id,
            template_by_id_minus_offset,
            template_id_offset,
        })
    }

    // This is made to match the method called "frame_dependency_definition()" in the spec.
    fn frame_dependency_definition(
        &mut self,
        shared_structure: &SharedStructure,
        template_id: u8,
        custom_flags: CustomFlags,
    ) -> ParseResult<FrameDependencyDefinition> {
        // The spec calls this "templateIndex"
        let template_id_minus_offset =
            (template_id + 64 - shared_structure.template_id_offset) % 64;
        let Some(template) = shared_structure.template_by_id_minus_offset.get(template_id_minus_offset as usize) else {
            return Err(ParseError::InvalidTemplateId);
        };
        // The spec calls this "FrameSpatialId"
        let spatial_layer_id = template.spatial_layer_id;
        // The spec calls this "FrameTemporalId"
        let temporal_layer_id = template.temporal_layer_id;
        // The spec calls this "frame_dti",
        let decode_target_indication_by_decode_target_index = if custom_flags.dtis {
            self.frame_dtis(shared_structure.decode_target_count)?
        } else {
            template
                .decode_target_indication_by_decode_target_index
                .clone()
        };
        // The spec calls this "FrameFdiff"
        let referred_frame_number_diffs = if custom_flags.fdiffs {
            self.frame_fdiffs()?
        } else {
            template.referred_relative_frame_numbers.clone()
        };
        // The spec calls this "frame_chain_fdiff"
        let previous_frame_number_diff_by_chain_index = if custom_flags.chains {
            self.frame_chains(shared_structure.chain_count)?
        } else {
            template
                .previous_relative_frame_number_by_chain_index
                .clone()
        };
        // The spec calls this  "FrameMaxWidth" and "FrameMaxHeight"
        let resolution = shared_structure
            .resolution_by_spatial_id
            .as_ref()
            .and_then(|resolution_by_spatial_id| {
                resolution_by_spatial_id.get(spatial_layer_id as usize)
            })
            .cloned();
        Ok(FrameDependencyDefinition {
            spatial_layer_id,
            temporal_layer_id,
            decode_target_indication_by_decode_target_index,
            referred_relative_frame_numbers: referred_frame_number_diffs,
            previous_relative_frame_number_by_chain_index:
                previous_frame_number_diff_by_chain_index,
            resolution,
        })
    }

    // This is made to match the method called "template_layers()" in the spec.
    fn template_layers(
        &mut self,
        decode_target_count: u8,
    ) -> ParseResult<Vec<SharedStructureTemplate>> {
        let mut templates = vec![SharedStructureTemplate {
            spatial_layer_id: 0,
            temporal_layer_id: 0,
            decode_target_indication_by_decode_target_index: Vec::with_capacity(
                decode_target_count as usize,
            ),
            referred_relative_frame_numbers: vec![],
            previous_relative_frame_number_by_chain_index: vec![],
        }];
        loop {
            // The spec says "used to determine spatial ID and temporal ID for the next Frame dependency template
            //   Table A.2 describes how the spatial ID and temporal ID values are determined.
            //   A next_layer_idc equal to 3 indicates that no more Frame dependency templates are present
            //   in the Frame dependency structure.
            //
            //   0 The next Frame dependency template has the same spatial ID and temporal ID as the current template
            //   1 The next Frame dependency template has the same spatial ID and temporal ID plus 1 compared with the current Frame dependency template.
            //   2 The next Frame dependency template has temporal ID equal to 0 and spatial ID plus 1 compared with the current Frame dependency template.
            //   3 No more Frame dependency templates are present in the Frame dependency structure."
            // Range: 0..=3
            let next_layer_idc = self.f(2)? as u8;
            let last = templates.last().unwrap();
            let next = match next_layer_idc {
                0 => {
                    // The spec says "same sid and tid"
                    // libwebrtc calls this "kSameLayer"
                    last.clone()
                }
                1 => {
                    // libwebrtc calls this "kNextTemporalLayer"
                    let mut next = last.clone();
                    next.temporal_layer_id = last
                        .temporal_layer_id
                        .checked_add(1)
                        .ok_or(ParseError::InvalidTemporalLayerId)?;
                    next
                }
                2 => {
                    // libwebrtc call this "kNextSpatialLayer"
                    let mut next = last.clone();
                    next.spatial_layer_id = last
                        .temporal_layer_id
                        .checked_add(1)
                        .ok_or(ParseError::InvalidSpatialLayerId)?;
                    next.temporal_layer_id = 0;
                    next
                }
                3 => {
                    // libwebrtc calls this "kNoMoreTemplates"
                    break;
                }
                _ => {
                    unreachable!();
                }
            };
            templates.push(next);
        }
        Ok(templates)
    }

    // This is made to match the method called "render_resolutions()" in the spec.
    fn render_resolutions(&mut self, max_spatial_id: u8) -> ParseResult<Vec<Resolution>> {
        let mut resolutions = Vec::with_capacity(max_spatial_id as usize);
        for _ in 0..=max_spatial_id {
            // The spec calls this "max_render_width_minus_1"
            // Range: 1..=65536
            let max_render_width = self.f(16)? + 1;
            // The spec calls this "max_render_height_minus_1"
            // Range: 1..=65536
            let max_render_height = self.f(16)? + 1;
            resolutions.push(Resolution {
                max_render_width,
                max_render_height,
            })
        }
        Ok(resolutions)
    }

    // This is made to match the method called "template_dtis()" in the spec.
    fn template_dtis(
        &mut self,
        templates: &mut Vec<SharedStructureTemplate>,
        decode_target_count: u8,
    ) -> ParseResult<()> {
        for template in templates {
            // The spec says "template_dti[templateIndex][]: an array of size dt_cnt_minus_one + 1
            //   containing Decode Target Indications for the Frame dependency template
            //   having index value equal to templateIndex.
            //   Table A.1 contains a description of the Decode Target Indication values."

            //   0 - Not present; No payload for this Decode target is present.
            //   1 D Discardable; Payload for this Decode target is present and discardable.
            //   2 S Switch;      Payload for this Decode target is present and switch is possible (Switch indication).
            //   3 R Required;    Payload for this Decode target is present but it is neither discardable nor is it a Switch indication."
            for _ in 0..decode_target_count {
                let template_dti = self.f(2)? as u8;
                let decode_target_indication =
                    DecodeTargetIndication::from_u2(template_dti).unwrap();
                template
                    .decode_target_indication_by_decode_target_index
                    .push(decode_target_indication);
            }
        }
        Ok(())
    }

    // This is made to match the method called "frame_dtis()" in the spec.
    fn frame_dtis(&mut self, decode_target_count: u8) -> ParseResult<Vec<DecodeTargetIndication>> {
        let mut frame_dtis = Vec::with_capacity(decode_target_count as usize);
        for _ in 0..decode_target_count {
            // The spec says "frame_dti[dtIndex]: Decode Target Indication describing the relationship between
            //   the current frame and the Decode target having index equal to dtIndex.
            //   Table A.1 contains a description of the Decode Target Indication values."
            let frame_dti = self.f(2)? as u8;
            let decode_target_indication = DecodeTargetIndication::from_u2(frame_dti).unwrap();
            frame_dtis.push(decode_target_indication);
        }
        Ok(frame_dtis)
    }

    // This is made to match the method called "template_fdiffs()" in the spec.
    fn template_fdiffs(&mut self, templates: &mut Vec<SharedStructureTemplate>) -> ParseResult<()> {
        for template in templates {
            loop {
                // The spec says "indicates the presence of a frame difference value.
                //   When the fdiff_follows_flag is set to 1, fdiff_minus_one MUST immediately follow;
                //   otherwise a value of 0 indicates no more frame difference values are present
                //   for the current Frame dependency template."
                // libwebrtc calls it "fdiff_follows"
                let fdiff_follows_flag = self.f1()?;
                if !fdiff_follows_flag {
                    break;
                }
                // The spec says: "the difference between frame_number and the frame_number of the Referred frame minus one.
                //   The calculation is done modulo the size of the frame_number field."
                // Range: 0..=15
                let fdiff_minus_one = self.f(4)? as RelativeFrameNumber;
                // The spec calls it "TemplateFdiff"
                // Range: 1..=16
                let frame_number_minus_referred_frame_number = fdiff_minus_one + 1;
                template
                    .referred_relative_frame_numbers
                    .push(frame_number_minus_referred_frame_number);
            }
        }
        Ok(())
    }

    // This is made to match the method called "frame_fdiffs()" in the spec.
    fn frame_fdiffs(&mut self) -> ParseResult<Vec<RelativeFrameNumber>> {
        let mut frame_fdiffs = Vec::new();
        loop {
            // The spec says "next_fdiff_size: indicates the size of following fdiff_minus_one syntax elements in 4-bit units.
            //   When set to a non-zero value, fdiff_minus_one MUST immediately follow;
            //   otherwise a value of 0 indicates no more frame difference values are present".
            // Possible values: 0, 4, 8, 12
            let frame_diff_size = (self.f(2)? as u8) * 4;
            if frame_diff_size == 0 {
                break;
            }
            // Range: 0..=4095
            let fdiff_minus_one = self.f(frame_diff_size)? as RelativeFrameNumber;
            // The spec says "FrameFdiff[FrameFdiffCnt] = fdiff_minus_one + 1"
            // Range: 1..=4096
            let frame_fdiff = fdiff_minus_one + 1;
            frame_fdiffs.push(frame_fdiff);
        }
        Ok(frame_fdiffs)
    }

    // This is made to match the method called "template_chains()" in the spec.
    fn template_chains(
        &mut self,
        templates: &mut Vec<SharedStructureTemplate>,
        decode_target_count: u8,
    ) -> ParseResult<(u8, Vec<ChainIndex>)> {
        // The spec says "chain_cnt: indicates the number of Chains.
        //   When set to zero, the Frame dependency structure does not utilize protection with Chains."
        // Range: 0-32
        let chain_count = self.ns(decode_target_count + 1)?;
        if chain_count == 0 {
            return Ok((chain_count, vec![]));
        }
        // The spec says "decode_target_protected_by[dtIndex]: the index of the Chain that protects Decode target
        //   with index equal to dtIndex.
        //   When chain_cnt > 0, each Decode target MUST be protected by exactly one Chain."
        // libwebrtc calls this "protected_by_chain"
        let mut protecting_chain_index_by_decode_target_index =
            Vec::with_capacity(decode_target_count as usize);
        for _ in 0..decode_target_count {
            // Range: 0..=31
            let protecting_chain_index = self.ns(chain_count)?;
            protecting_chain_index_by_decode_target_index.push(protecting_chain_index);
        }
        for template in templates {
            // The spec says "template_chain_fdiff[templateIndex][]: an array of size chain_cnt containing
            //   frame_chain_fdiff values for the Frame dependency template having index value equal to templateIndex.
            //   In a template, the values of frame_chain_fdiff can be in the range 0 to 15, inclusive.""
            for _ in 0..chain_count {
                // Range: 0..=15
                let previous_frame_number_diff = self.f(4)? as RelativeFrameNumber;
                template
                    .previous_relative_frame_number_by_chain_index
                    .push(previous_frame_number_diff)
            }
        }
        Ok((chain_count, protecting_chain_index_by_decode_target_index))
    }

    // This is made to match the method called "frame_chains()" in the spec.
    fn frame_chains(&mut self, chain_count: u8) -> ParseResult<Vec<RelativeFrameNumber>> {
        let mut previous_frame_number_diff_by_chain_index =
            Vec::with_capacity(chain_count as usize);
        for _ in 0..chain_count {
            // The spec says "frame_chain_fdiff[chainIdx]: indicates the difference between
            //   the frame_number and the frame_number of the previous frame in the Chain having index equal to chainIdx.
            //   A value of 0 indicates no previous frames are needed for the Chain.
            //   For example, when a packet containing frame_chain_fdiff[chainIdx]=3 and frame_number=112 the previous frame
            //   in the Chain with index equal to chainIdx has frame_number=109.
            //   The calculation is done modulo the size of the frame_number field."
            // Range: 0..=255
            let frame_chain_fdiff = self.f(8)? as RelativeFrameNumber;
            previous_frame_number_diff_by_chain_index.push(frame_chain_fdiff);
        }
        Ok(previous_frame_number_diff_by_chain_index)
    }

    // This is made to match the method called "ns()" in the spec.
    // A better name for "ns" might be "non_symmetric_u8()"
    // The spec calls possible_values_count just "n".
    fn ns(&mut self, possible_values_count: u8) -> ParseResult<u8> {
        if possible_values_count == 0 {
            // %%%% what?
            return Ok(0);
        }
        // Range: 1..=8
        let w = 8 - possible_values_count.leading_zeros() as u8;
        // Range of (1 << w): 2..=256, so need 16 bits temporarily
        // Range of m: 1..=128
        let m = (1u16 << w) - (possible_values_count as u16);
        // Range: 0..=127
        let v = self.f(w - 1)? as u16;
        if v < m {
            Ok(v as u8)
        } else {
            // Range of v: m..=127
            // Range of (v << 1): 2m..=354, so needs 16 bits temporarily
            let extra_bit = self.f(1)? as u16;
            Ok(((v << 1) - m + extra_bit) as u8)
        }
    }

    // This is made to match the method called "f(n)" in the spec.
    // A better name might for "f(n) might be "fixed_width_u32()"
    fn f(&mut self, n: u8) -> ParseResult<u32> {
        self.bit_stream.read_u32(n).ok_or(ParseError::NotEnoughBits)
    }

    // As faster way to do f(1)
    fn f1(&mut self) -> ParseResult<bool> {
        self.bit_stream.read_bit().ok_or(ParseError::NotEnoughBits)
    }

    fn is_empty(&self) -> bool {
        self.bit_stream.is_empty()
    }
}

struct MandatoryFields {
    // The spec says "MUST be set to 1 if the first payload byte of the RTP packet is the beginning of a new frame,
    //   and MUST be set to 0 otherwise. Note that this frame might not be the first frame of a temporal unit."
    // libwebrtc calls this "first_packet_in_frame"
    start_of_frame: bool,
    // The spec says "MUST be set to 1 for the final RTP packet of a frame, and MUST be set to 0 otherwise.
    //   Note that, if spatial scalability is in use, more frames from the same temporal unit may follow."
    // libwebrtc calls this "last_packet_in_frame"
    end_of_frame: bool,
    // The spec says: "is represented using 16 bits and increases strictly monotonically in decode order.
    //   frame_number MAY start on a random number, and MUST wrap after reaching the maximum value.
    //   All packets of the same frame MUST have the same frame_number value.
    //   Note: frame_number is not the same as Frame ID in AV1 specification."
    frame_number: TruncatedFrameNumber,
    // The spec says "frame_dependency_template_id is the ID of the Frame dependency template to use.
    //   MUST be in the range of template_id_offset to (template_id_offset + TemplateCnt - 1), inclusive.
    //   frame_dependency_template_id MUST be the same for all packets of the same frame."
    template_id: u8, // 0-63,
}

struct CustomFlags {
    // The spec says "custom_dtis_flag indicates the presence of frame_dtis.
    //    When set to 1, frame_dtis MUST be present. Otherwise, frame_dtis MUST NOT be present."
    dtis: bool,
    // The spec says "custom_fdiffs_flag indicates the presence of frame_fdiffs.
    //   When set to 1, frame_fdiffs MUST be present. Otherwise, frame_fdiffs MUST NOT be present."
    fdiffs: bool,
    // The spec says: "custom_chains_flag indicates the presence of frame_chain_fdiff.
    //   When set to 1, frame_chain_fdiff MUST be present. Otherwise, frame_chain_fdiff MUST NOT be present."
    chains: bool,
}

struct ExtendedFields {
    // %%% call just structure?
    shared_structure: Option<SharedStructure>,
    active_decode_targets_bitmask: Option<u32>,
}

struct FrameDependencyDefinition {
    // The spec calls this "FrameSpatialId"
    spatial_layer_id: SpatialLayerId,
    // The spec calls this "FrameTemporalId"
    temporal_layer_id: TemporalLayerId,
    // The spec calls this "frame_dti"
    // libwebrtc calls this "decode_target_indications"
    decode_target_indication_by_decode_target_index: Vec<DecodeTargetIndication>,
    // The spec calls these "FrameFdiff"
    // libwebrtc calls these "frame_dependencies"
    // Range: 1-4096 for each
    referred_relative_frame_numbers: Vec<RelativeFrameNumber>,
    // The spec calls this "frame_chain_fdiff"
    // Range: 0-255 for each
    previous_relative_frame_number_by_chain_index: Vec<RelativeFrameNumber>,
    // The spec calls thes "FrameMaxWidth" and "FrameMaxHeight"
    resolution: Option<Resolution>,
}

// A handy way to read bits from a slice.
// TODO: Move to a common place where this can be reused.
struct BitStream<'a> {
    bytes: &'a [u8],
    bit_index: u8,
}

impl<'a> BitStream<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        BitStream {
            bytes,
            bit_index: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[inline(always)]
    fn read_u32(&mut self, bit_count: u8) -> Option<u32> {
        let bit_count_remaining_in_byte0 = 8 - self.bit_index;
        let left_bit_count = std::cmp::min(bit_count_remaining_in_byte0, bit_count);
        let right_bit_count = (bit_count.saturating_sub(bit_count_remaining_in_byte0)) % 8;
        let middle_bit_count = bit_count - left_bit_count - right_bit_count;
        let middle_byte_count = middle_bit_count / 8;

        let left = self.read_u8_up_until_end_of_byte0(left_bit_count)? as u32;
        let middle: u32 = self.read_u32_from_aligned_bytes(middle_byte_count as usize)?;
        let right = self.read_u8_up_until_end_of_byte0(right_bit_count)? as u32;

        Some((((left << middle_bit_count) | middle) << right_bit_count) | right)
    }

    // #[inline(always)]
    fn read_bit(&mut self) -> Option<bool> {
        let (byte0, after_byte0) = self.bytes.split_first()?;
        let bit = Self::read_ms_bit_of_byte(*byte0, self.bit_index);
        self.bit_index += 1;
        if self.bit_index >= 8 {
            self.bytes = after_byte0;
            self.bit_index = 0;
        }
        bit
    }

    #[inline(always)]
    fn read_u8_up_until_end_of_byte0(&mut self, bit_count: u8) -> Option<u8> {
        if bit_count == 0 {
            return Some(0);
        }
        let bit_index_start = self.bit_index;
        let bit_index_end = self.bit_index.checked_add(bit_count)?;
        if bit_index_end > 8 {
            return None;
        }
        let (byte0, after_byte0) = self.bytes.split_first()?;
        let bits = Self::read_ms_bits_of_byte(*byte0, bit_index_start..bit_index_end);
        self.bit_index += bit_count;
        if self.bit_index >= 8 {
            self.bytes = after_byte0;
            self.bit_index = 0;
        }
        bits
    }

    fn read_u32_from_aligned_bytes(&mut self, byte_count: usize) -> Option<u32> {
        if byte_count == 0 {
            return Some(0);
        }
        let bytes = self.read_aligned_bytes(byte_count)?;
        Some(Self::u32_from_bytes(bytes))
    }

    fn read_aligned_bytes(&mut self, byte_count: usize) -> Option<&[u8]> {
        if self.bit_index > 0 {
            return None;
        }
        if byte_count > self.bytes.len() {
            return None;
        }
        let (left, right) = self.bytes.split_at(byte_count);
        self.bytes = right;
        Some(left)
    }

    fn u32_from_bytes(bytes: &[u8]) -> u32 {
        let mut result = 0u32;
        for byte in bytes {
            result = result.wrapping_shl(8) | (*byte as u32);
        }
        result
    }

    fn read_ls_bit_of_u32(word: u32, bit_index: u8) -> Option<bool> {
        if bit_index > 32 {
            return None;
        }
        // Alternative: (word & (1u8 << (bit_index as u32))) > 0
        Some(((word >> (bit_index as u32)) & 1) > 0)
    }

    fn read_ms_bit_of_byte(byte: u8, bit_index: u8) -> Option<bool> {
        if bit_index > 7 {
            return None;
        }
        Some(((byte >> (7 - bit_index)) & 0b1) > 0)
    }

    fn read_ms_bits_of_byte(byte: u8, bit_index_range: std::ops::Range<u8>) -> Option<u8> {
        if bit_index_range.end == 0 || bit_index_range.end > 8 {
            return None;
        }
        Some((byte >> (8 - bit_index_range.end)) & (0b1111_1111 >> (8 - bit_index_range.len())))
    }
}

// %%%% Add tests
