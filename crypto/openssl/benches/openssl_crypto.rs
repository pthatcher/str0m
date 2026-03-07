//! Criterion benchmarks for OpenSSL crypto operations.
//!
//! Run via:
//!
//! ```sh
//! cargo bench -p str0m-openssl
//! ```

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use str0m_openssl::default_provider;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

/// AES-GCM tag length in bytes (128-bit tag).
const GCM_TAG_LEN: usize = 16;

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let provider = default_provider();
    let iv = [0x01u8; 12];
    let aad = [0xAAu8; 12];

    let mut group = c.benchmark_group("aes_gcm_128_encrypt");
    for size in [1024] {
        //64, 256, 1024, 4096] {
        let input = vec![0xBBu8; size];
        let mut output = vec![0u8; size + GCM_TAG_LEN];
        let mut cipher = provider
            .srtp_provider
            .aead_aes_128_gcm()
            .create_cipher([0x42u8; 16], true);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                cipher
                    .encrypt(&iv, &aad, &input, &mut output)
                    .expect("encrypt failed");
            });
        });
    }
    group.finish();

    // let mut group = c.benchmark_group("aes_gcm_256_encrypt");
    // for size in [64, 256, 1024, 4096] {
    //     let input = vec![0xBBu8; size];
    //     let mut output = vec![0u8; size + GCM_TAG_LEN];
    //     let mut cipher = provider
    //         .srtp_provider
    //         .aead_aes_256_gcm()
    //         .create_cipher([0x42u8; 32], true);

    //     group.throughput(Throughput::Bytes(size as u64));
    //     group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
    //         b.iter(|| {
    //             cipher
    //                 .encrypt(&iv, &aad, &input, &mut output)
    //                 .expect("encrypt failed");
    //         });
    //     });
    // }
    // group.finish();
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let provider = default_provider();
    let iv = [0x01u8; 12];
    let aad = [0xAAu8; 12];

    let mut group = c.benchmark_group("aes_gcm_128_decrypt");
    for size in [64, 256, 1024, 4096] {
        // Encrypt first to get valid ciphertext + tag.
        let plaintext = vec![0xBBu8; size];
        let mut ciphertext = vec![0u8; size + GCM_TAG_LEN];
        let key = [0x42u8; 16];
        let mut enc_cipher = provider
            .srtp_provider
            .aead_aes_128_gcm()
            .create_cipher(key, true);
        enc_cipher
            .encrypt(&iv, &aad, &plaintext, &mut ciphertext)
            .expect("setup encrypt failed");

        let mut dec_cipher = provider
            .srtp_provider
            .aead_aes_128_gcm()
            .create_cipher(key, false);
        let mut output = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                dec_cipher
                    .decrypt(&iv, &[&aad], &ciphertext, &mut output)
                    .expect("decrypt failed");
            });
        });
    }
    group.finish();
}

fn bench_hmac_sha1(c: &mut Criterion) {
    let provider = default_provider();
    let key = [0x0Bu8; 20];

    let mut group = c.benchmark_group("hmac_sha1");
    for size in [64, 256, 1024, 4096] {
        let data = vec![0xCCu8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                provider.sha1_hmac_provider.sha1_hmac(&key, &[&data]);
            });
        });
    }
    group.finish();
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let key_bytes = [0x0Bu8; 32];

    let mut group = c.benchmark_group("hmac_sha256");
    for size in [64, 256, 1024, 4096] {
        let data = vec![0xCCu8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let pkey = PKey::hmac(&key_bytes).expect("valid hmac key");
                let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("valid signer");
                signer.update(&data).expect("signer update");
                let mut hmac = [0u8; 32];
                signer.sign(&mut hmac).expect("sign to array");
                hmac
            });
        });
    }
    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let provider = default_provider();

    let mut group = c.benchmark_group("sha256");
    for size in [64, 256, 1024, 4096] {
        let data = vec![0xCCu8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                provider.sha256_provider.sha256(&data);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_aes_gcm_encrypt,
    // bench_aes_gcm_decrypt,
    // bench_hmac_sha1,
    // bench_hmac_sha256,
    // bench_sha256,
);
criterion_main!(benches);
