//! Windows SChannel + CNG implementation of cryptographic functions.

use super::{CryptoError, CryptoProvider, CryptoProviderId};

mod cert;
mod dtls;
mod sha1;
mod srtp;

pub(crate) fn create_crypto_provider() -> CryptoProvider {
    CryptoProvider {
        crypto_provider_id: CryptoProviderId::WinCrypto,
        create_dtls_identity_impl: cert::create_dtls_identity_impl,
        create_aes_128_cm_sha1_80_cipher_impl: srtp::Aes128CmSha1_80Impl::new,
        create_aead_aes_128_gcm_cipher_impl: srtp::AeadAes128GcmImpl::new,
        srtp_aes_128_ecb_round_impl: srtp::srtp_aes_128_ecb_round,
        sha1_hmac_impl: sha1::sha1_hmac,
    }
}

pub use str0m_wincrypto::WinCryptoError;
