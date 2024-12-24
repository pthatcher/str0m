use crate::crypto::dtls::{DtlsCertOptions, DtlsPKeyType, DTLS_CERT_IDENTITY};
use crate::crypto::Fingerprint;
use std::sync::Arc;
use str0m_wincrypto::WinCryptoError;

#[derive(Clone, Debug)]
pub struct WinCryptoDtlsCert {
    pub(crate) certificate: Arc<str0m_wincrypto::Certificate>,
}

impl WinCryptoDtlsCert {
    pub fn new(options: DtlsCertOptions) -> Self {
        let common_name = options
            .common_name
            .map_or(DTLS_CERT_IDENTITY, |s| s.as_str());
        let use_ecdsa_keys = match options.pkey_type {
            DtlsPKeyType::Rsa => false,
            DtlsPKeyType::Ecdsa => true,
        };

        let certificate = Arc::new(
            str0m_wincrypto::Certificate::new_self_signed(
                use_ecdsa_keys,
                &format!("CN={}", common_name),
            )
            .expect("Failed to create self-signed certificate"),
        );
        Self { certificate }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        create_fingerprint(&self.certificate).expect("Failed to calculate fingerprint")
    }
}

pub(super) fn create_fingerprint(
    certificate: &str0m_wincrypto::Certificate,
) -> Result<Fingerprint, WinCryptoError> {
    certificate
        .sha256_fingerprint()
        .map(|f| create_sha256_fingerprint(&f))
}

pub(super) fn create_sha256_fingerprint(bytes: &[u8; 32]) -> Fingerprint {
    Fingerprint {
        hash_func: "sha-256".into(),
        bytes: bytes.to_vec(),
    }
}
