use super::WinCryptoError;
use windows::{
    core::{HSTRING, PWSTR,PSTR, w},
    Win32::{Foundation::GetLastError, Security::Cryptography::{
        szOID_ECDSA_SHA256, szOID_RSA_SHA256RSA, BCryptCreateHash, BCryptDestroyHash,
        BCryptFinishHash, BCryptHashData, CertCreateSelfSignCertificate,
        CertFreeCertificateContext, CertStrToNameW, BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALG_HANDLE,
        CERT_CONTEXT, CERT_CREATE_SELFSIGN_FLAGS, CERT_OID_NAME_STR, CRYPT_ALGORITHM_IDENTIFIER,
        CRYPT_INTEGER_BLOB, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, X509_ASN_ENCODING, CRYPT_KEY_PROV_INFO,
        NCRYPT_SILENT_FLAG, MS_KEY_STORAGE_PROVIDER, CRYPT_KEY_FLAGS, NCryptFinalizeKey, NCryptCreatePersistedKey, CERT_KEY_SPEC, NCRYPT_FLAGS,
        NCRYPT_ECDSA_P256_ALGORITHM, NCryptOpenStorageProvider, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
    }},
};

/// Certificate wraps the CERT_CONTEXT pointer, so that it can be destroyed
/// when it is no longer used. Because it is tracked, it is important that
/// Certificate does NOT implement Clone/Copy, otherwise we could destroy the
/// Certificate too early. It is also why access to the certificate pointer
/// should remain hidden.
#[derive(Debug)]
pub struct Certificate(pub(crate) *const CERT_CONTEXT);
// SAFETY: CERT_CONTEXT pointers are safe to send between threads.
unsafe impl Send for Certificate {}
// SAFETY: CERT_CONTEXT pointers are safe to send between threads.
unsafe impl Sync for Certificate {}

impl Certificate {
    pub fn new_self_signed(use_ecdsa_keys: bool, subject: &str) -> Result<Self, WinCryptoError> {
        let subject = HSTRING::from(subject);
        let mut subject_blob_buffer = vec![0u8; 256];
        let mut subject_blob = CRYPT_INTEGER_BLOB {
            cbData: subject_blob_buffer.len() as u32,
            pbData: subject_blob_buffer.as_mut_ptr(),
        };

        let mut h_provider = NCRYPT_PROV_HANDLE::default();
        let mut h_key = NCRYPT_KEY_HANDLE::default();
        let key_prov_info = CRYPT_KEY_PROV_INFO {
            pwszContainerName: PWSTR::from_raw(w!("YourKeyContainer").as_ptr() as *mut u16),
            pwszProvName: PWSTR::from_raw(MS_KEY_STORAGE_PROVIDER.as_ptr() as *mut u16),
            dwProvType: 0,
            dwFlags: CRYPT_KEY_FLAGS(0),
            cProvParam: 0,
            rgProvParam: std::ptr::null_mut(),
            dwKeySpec: 0,
        };

        let (key, key_prov_info_ref, signature_algorithm) = if use_ecdsa_keys {
            // Use EC-256 which corresponds to NID_X9_62_prime256v1
            unsafe {
                NCryptOpenStorageProvider(&mut h_provider, MS_KEY_STORAGE_PROVIDER, 0)?;
                NCryptCreatePersistedKey(h_provider, &mut h_key, NCRYPT_ECDSA_P256_ALGORITHM, None, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0))?;
                NCryptFinalizeKey(h_key, NCRYPT_SILENT_FLAG)?;
            }
            (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(h_key.0),
            Some(&key_prov_info as *const CRYPT_KEY_PROV_INFO),
            CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: PSTR::from_raw(szOID_ECDSA_SHA256.as_ptr() as *mut u8),
                Parameters: CRYPT_INTEGER_BLOB::default(),
            })
        } else {
            // Use RSA-SHA256 for the signature, since SHA1 is deprecated.
            (
                HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0),
                None,
                CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: PSTR::from_raw(szOID_RSA_SHA256RSA.as_ptr() as *mut u8),
                Parameters: CRYPT_INTEGER_BLOB::default(),
            })
        };

        // SAFETY: The Windows APIs accept references, so normal borrow checker
        // behaviors work for those uses. The name_blob has a pointer to the buffer
        // which must exist for the duration of the unsafe block.
        unsafe {
            CertStrToNameW(
                X509_ASN_ENCODING,
                &subject,
                CERT_OID_NAME_STR,
                None,
                Some(subject_blob.pbData),
                &mut subject_blob.cbData,
                None,
            )?;

            // Generate the self-signed cert.
            let cert_context = CertCreateSelfSignCertificate(
                key,
                &subject_blob,
                CERT_CREATE_SELFSIGN_FLAGS(0),
                key_prov_info_ref,
                Some(&signature_algorithm),
                None,
                None,
                None,
            );

            if cert_context.is_null() {
                let win_err = GetLastError();
                Err(WinCryptoError(
                    format!("Failed to generate self-signed certificate: {:?}", win_err),
                ))
            } else {
                Ok(Self(cert_context))
            }
        }
    }

    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], WinCryptoError> {
        let mut hash = [0u8; 32];
        let mut hash_handle = BCRYPT_HASH_HANDLE::default();

        // SAFETY: The Windows APIs accept references, so normal borrow checker
        // behaviors work for those uses.
        unsafe {
            // Create the hash instance.
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                &mut hash_handle,
                None,
                None,
                0,
            )) {
                return Err(WinCryptoError(format!("Failed to create hash: {e}")));
            }

            // Hash the certificate contents.
            let cert_info = *self.0;
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptHashData(
                hash_handle,
                std::slice::from_raw_parts(
                    cert_info.pbCertEncoded,
                    cert_info.cbCertEncoded as usize,
                ),
                0,
            )) {
                return Err(WinCryptoError(format!("Failed to hash data: {e}")));
            }

            // Grab the result of the hash.
            WinCryptoError::from_ntstatus(BCryptFinishHash(hash_handle, &mut hash, 0))?;

            // Destroy the allocated hash.
            WinCryptoError::from_ntstatus(BCryptDestroyHash(hash_handle))?;
        }
        Ok(hash)
    }
}

impl From<*const CERT_CONTEXT> for Certificate {
    fn from(value: *const CERT_CONTEXT) -> Self {
        Self(value)
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: The Certificate is no longer usable, so it's safe to pass the pointer
        // to Windows for release.
        unsafe {
            _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::Security::Cryptography::{
            szOID_ECC_PUBLIC_KEY, szOID_RSA_RSA,
        };
    use std::ffi::CStr;
    
    #[test]
    fn verify_self_signed_rsa() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC").unwrap();

        // Verify it is self-signed.
        unsafe {
            assert_eq!(CStr::from_ptr((*(*cert.0).pCertInfo).SubjectPublicKeyInfo.Algorithm.pszObjId.0 as *const i8), 
                CStr::from_ptr(szOID_RSA_RSA.as_ptr() as *const i8));
            let subject = (*(*cert.0).pCertInfo).Subject;
            let subject = std::slice::from_raw_parts(subject.pbData, subject.cbData as usize);
            let issuer = (*(*cert.0).pCertInfo).Issuer;
            let issuer = std::slice::from_raw_parts(issuer.pbData, issuer.cbData as usize);
            assert_eq!(issuer, subject);
        }
    }

    #[test]
    fn verify_self_signed_ecdsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=WebRTC").unwrap();

        // Verify it is self-signed.
        unsafe {
            assert_eq!(CStr::from_ptr((*(*cert.0).pCertInfo).SubjectPublicKeyInfo.Algorithm.pszObjId.0 as *const i8), 
                CStr::from_ptr(szOID_ECC_PUBLIC_KEY.as_ptr() as *const i8));
            let subject = (*(*cert.0).pCertInfo).Subject;
            let subject = std::slice::from_raw_parts(subject.pbData, subject.cbData as usize);
            let issuer = (*(*cert.0).pCertInfo).Issuer;
            let issuer = std::slice::from_raw_parts(issuer.pbData, issuer.cbData as usize);
            assert_eq!(issuer, subject);
        }
    }

    #[test]
    fn verify_fingerprint_rsa() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC").unwrap();
        let fingerprint = cert.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
    }

    #[test]
    fn verify_fingerprint_ecdsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=WebRTC").unwrap();
        let fingerprint = cert.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
    }
}
