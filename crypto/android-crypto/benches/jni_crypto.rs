//! Criterion benchmarks for android-crypto JNI operations.
//!
//! Run on an Android device/emulator via:
//!
//! ```sh
//! cargo ndk -t <target> bench -p str0m-android-crypto
//! ```

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use str0m_android_crypto::jni_crypto;

/// AES-GCM tag length in bytes (128-bit tag).
const GCM_TAG_LEN: usize = 16;

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let key_128 = [0x42u8; 16];
    let iv = [0x01u8; 12];
    let aad = [0xAAu8; 12];

    let mut group = c.benchmark_group("aes_gcm_128_encrypt");
    for size in [1024] {
        //64, 256, 1024, 4096] {
        let input = vec![0xBBu8; size];
        let mut output = vec![0u8; size + GCM_TAG_LEN];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                jni_crypto::aes_gcm_encrypt(&key_128, &iv, &input, &aad, &mut output)
                    .expect("encrypt failed");
            });
        });
    }
    group.finish();

    // let key_256 = [0x42u8; 32];

    // let mut group = c.benchmark_group("aes_gcm_256_encrypt");
    // for size in [64, 256, 1024, 4096] {
    //     let input = vec![0xBBu8; size];
    //     let mut output = vec![0u8; size + GCM_TAG_LEN];

    //     group.throughput(Throughput::Bytes(size as u64));
    //     group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
    //         b.iter(|| {
    //             jni_crypto::aes_gcm_encrypt(&key_256, &iv, &input, &aad, &mut output)
    //                 .expect("encrypt failed");
    //         });
    //     });
    // }
    // group.finish();
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let key_128 = [0x42u8; 16];
    let iv = [0x01u8; 12];
    let aad = [0xAAu8; 12];

    let mut group = c.benchmark_group("aes_gcm_128_decrypt");
    for size in [64, 256, 1024, 4096] {
        // Encrypt first to get valid ciphertext + tag.
        let plaintext = vec![0xBBu8; size];
        let mut ciphertext = vec![0u8; size + GCM_TAG_LEN];
        jni_crypto::aes_gcm_encrypt(&key_128, &iv, &plaintext, &aad, &mut ciphertext)
            .expect("setup encrypt failed");

        let mut output = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                jni_crypto::aes_gcm_decrypt(&key_128, &iv, &ciphertext, &aad, &mut output)
                    .expect("decrypt failed");
            });
        });
    }
    group.finish();
}

fn bench_hmac_sha1(c: &mut Criterion) {
    let key = [0x0Bu8; 20];

    let mut group = c.benchmark_group("hmac_sha1");
    for size in [64, 256, 1024, 4096] {
        let data = vec![0xCCu8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                jni_crypto::hmac_sha1(&key, &data).expect("hmac_sha1 failed");
            });
        });
    }
    group.finish();
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let key = [0x0Bu8; 32];

    let mut group = c.benchmark_group("hmac_sha256");
    for size in [64, 256, 1024, 4096] {
        let data = vec![0xCCu8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                jni_crypto::hmac_sha256(&key, &data).expect("hmac_sha256 failed");
            });
        });
    }
    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for size in [64, 256, 1024, 4096] {
        let data = vec![0xCCu8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                jni_crypto::sha256(&data).expect("sha256 failed");
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
