use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    #[cfg(feature = "_internal_test_exports")]
    PassThrough,
    Aes128CmSha1_80,
    AeadAes128Gcm,
}

#[allow(dead_code)]
impl SrtpProfile {
    // All the profiles we support, ordered from most preferred to least.
    pub(crate) const ALL: &'static [SrtpProfile] =
        &[SrtpProfile::AeadAes128Gcm, SrtpProfile::Aes128CmSha1_80];

    /// The length of keying material to extract from the DTLS session in bytes.
    #[rustfmt::skip]
    pub(crate) fn keying_material_len(&self) -> usize {
        match self {
            #[cfg(feature = "_internal_test_exports")]
            SrtpProfile::PassThrough => 0,
             // MASTER_KEY_LEN * 2 + MASTER_SALT * 2
             // TODO: This is a duplication of info that is held in srtp.rs, because we
             // don't want a dependency in that direction.
            SrtpProfile::Aes128CmSha1_80 => 16 * 2 + 14 * 2,
            SrtpProfile::AeadAes128Gcm   => 16 * 2 + 12 * 2,
        }
    }
}

pub mod aes_128_cm_sha1_80 {
    use std::panic::UnwindSafe;

    use crate::crypto::{CryptoContext, CryptoError};

    pub const KEY_LEN: usize = 16;
    pub const SALT_LEN: usize = 14;
    pub const HMAC_KEY_LEN: usize = 20;
    pub const HMAC_TAG_LEN: usize = 10;
    pub type AesKey = [u8; 16];
    pub type RtpSalt = [u8; 14];
    pub type RtpIv = [u8; 16];

    pub trait CipherCtx: UnwindSafe + Send + Sync {
        fn encrypt(
            &mut self,
            iv: &RtpIv,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), CryptoError>;

        fn decrypt(
            &mut self,
            iv: &RtpIv,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), CryptoError>;
    }

    pub fn rtp_hmac(
        ctx: &CryptoContext,
        key: &[u8],
        buf: &mut [u8],
        srtp_index: u64,
        hmac_start: usize,
    ) {
        let roc = (srtp_index >> 16) as u32;
        let tag = ctx.sha1_hmac(key, &[&buf[..hmac_start], &roc.to_be_bytes()]);
        buf[hmac_start..(hmac_start + HMAC_TAG_LEN)].copy_from_slice(&tag[0..HMAC_TAG_LEN]);
    }

    pub fn rtp_verify(
        ctx: &CryptoContext,
        key: &[u8],
        buf: &[u8],
        srtp_index: u64,
        cmp: &[u8],
    ) -> bool {
        let roc = (srtp_index >> 16) as u32;
        let tag = ctx.sha1_hmac(key, &[buf, &roc.to_be_bytes()]);
        &tag[0..HMAC_TAG_LEN] == cmp
    }

    pub fn rtp_iv(salt: RtpSalt, ssrc: u32, srtp_index: u64) -> RtpIv {
        let mut iv = [0; 16];
        let ssrc_be = ssrc.to_be_bytes();
        let srtp_be = srtp_index.to_be_bytes();
        iv[4..8].copy_from_slice(&ssrc_be);
        for i in 0..8 {
            iv[i + 6] ^= srtp_be[i];
        }
        for i in 0..14 {
            iv[i] ^= salt[i];
        }
        iv
    }

    pub fn rtcp_hmac(ctx: &CryptoContext, key: &[u8], buf: &mut [u8], hmac_index: usize) {
        let tag = ctx.sha1_hmac(key, &[&buf[0..hmac_index]]);

        buf[hmac_index..(hmac_index + HMAC_TAG_LEN)].copy_from_slice(&tag[0..HMAC_TAG_LEN]);
    }

    pub fn rtcp_verify(ctx: &CryptoContext, key: &[u8], buf: &[u8], cmp: &[u8]) -> bool {
        let tag = ctx.sha1_hmac(key, &[buf]);

        &tag[0..HMAC_TAG_LEN] == cmp
    }
}

pub mod aead_aes_128_gcm {
    use std::panic::UnwindSafe;

    use crate::crypto::CryptoError;

    pub const KEY_LEN: usize = 16;
    pub const SALT_LEN: usize = 12;
    pub const RTCP_AAD_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;
    pub const IV_LEN: usize = 12;
    pub type AeadKey = [u8; KEY_LEN];
    pub type RtpSalt = [u8; SALT_LEN];
    pub type RtpIv = [u8; SALT_LEN];

    pub trait CipherCtx: UnwindSafe + Send + Sync {
        fn encrypt(
            &mut self,
            iv: &[u8; IV_LEN],
            aad: &[u8],
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), CryptoError>;

        fn decrypt(
            &mut self,
            iv: &[u8; IV_LEN],
            aads: &[&[u8]],
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, CryptoError>;
    }

    pub fn rtp_iv(salt: RtpSalt, ssrc: u32, roc: u32, seq: u16) -> RtpIv {
        // See: https://www.rfc-editor.org/rfc/rfc7714#section-8.1

        // TODO: See if this is faster if rewritten for u128
        let mut iv = [0; SALT_LEN];

        let ssrc_be = ssrc.to_be_bytes();
        let roc_be = roc.to_be_bytes();
        let seq_be = seq.to_be_bytes();

        iv[2..6].copy_from_slice(&ssrc_be);
        iv[6..10].copy_from_slice(&roc_be);
        iv[10..12].copy_from_slice(&seq_be);

        // XOR with salt
        for i in 0..SALT_LEN {
            iv[i] ^= salt[i];
        }

        iv
    }

    pub fn rtcp_iv(salt: RtpSalt, ssrc: u32, srtp_index: u32) -> RtpIv {
        // See: https://www.rfc-editor.org/rfc/rfc7714#section-9.1
        // TODO: See if this is faster if rewritten for u128
        let mut iv = [0; SALT_LEN];

        let ssrc_be = ssrc.to_be_bytes();
        let srtp_be = srtp_index.to_be_bytes();

        iv[2..6].copy_from_slice(&ssrc_be);
        iv[8..12].copy_from_slice(&srtp_be);

        // XOR with salt
        for i in 0..SALT_LEN {
            iv[i] ^= salt[i];
        }

        iv
    }
}
impl fmt::Display for SrtpProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "_internal_test_exports")]
            SrtpProfile::PassThrough => write!(f, "PassThrough"),
            SrtpProfile::Aes128CmSha1_80 => write!(f, "SRTP_AES128_CM_SHA1_80"),
            SrtpProfile::AeadAes128Gcm => write!(f, "SRTP_AEAD_AES_128_GCM"),
        }
    }
}
