use super::{FeedbackMessageType, PayloadType, RtcpHeader, RtcpPacket};
use super::{RtcpType, Ssrc};

/// Picture loss indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vsr {
    /// Sender of this feedback. Mostly irrelevant, but part of RTCP packets.
    pub sender_ssrc: Ssrc,
    /// The SSRC.
    pub ssrc: Ssrc,
    /// The MSI being requested.
    pub msi: u32,
    /// The request_id.
    pub request_id: u16,
}

impl RtcpPacket for Vsr {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::PayloadSpecificFeedback,
            feedback_message_type: FeedbackMessageType::PayloadFeedback(
                PayloadType::ApplicationLayer,
            ),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        25
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        self.header().write_to(&mut buf[..4]);
        buf[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        buf[12..16].copy_from_slice(&[
            0x00, 0x01, 0x00, 0x58, // VSR Type, and Len of FCI in bytes
        ]);
        buf[16..20].copy_from_slice(&self.msi.to_be_bytes());
        buf[20..22].copy_from_slice(&self.request_id.to_be_bytes());
        buf[22..100].copy_from_slice(&[
            0x00, 0x00, // Request ID (Offset = 20, 2 bytes)
            0x00, 0x00, 0x01, 0x44, // Version and Reserved
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x6b, 0x01, 0x06, 0x02, // PT (Offset = 32, 1 byte [107 is H264])
            0x07, 0x80, 0x04, 0x38, // Width (Offset = 36) and Height (Offset = 38)
            0x00, 0x06, 0x1a, 0x80, // Min bitrate (Offset = 40, 4 bytes)
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x00, 0x01, // Bitrate per level
            0x00, 0x01, 0x00, 0x00, // Bitrate histogram (20 bytes)
            0x00, 0x00, 0x00, 0x00, // --
            0x00, 0x00, 0x00, 0x00, // --
            0x00, 0x00, 0x00, 0x00, // --
            0x00, 0x00, 0x00, 0x00, // -- End histogram
            0x00, 0x00, 0x00, 0x10, // Framerate bit mask
            0x00, 0x01, 0x00, 0x00, // Number MUST (2 bytes), Number MAY (2 bytes)
            0x00, 0x01, 0x00, 0x00, // Quality Report Histogram (16 bytes)
            0x00, 0x00, 0x00, 0x00, // --
            0x00, 0x00, 0x00, 0x00, // --
            0x00, 0x00, 0x00, 0x00, // -- End histogram
            0x00, 0x1f, 0xa4, 0x00, // Max pixels (4 bytes)
        ]);
        100
    }
}

impl<'a> TryFrom<&'a [u8]> for Vsr {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 100 {
            return Err("Vsr less than 100 bytes");
        }

        let sender_ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]).into();
        let msi = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]).into();
        let request_id = u16::from_be_bytes([buf[20], buf[21]]).into();

        Ok(Vsr {
            sender_ssrc,
            ssrc,
            msi,
            request_id,
        })
    }
}
