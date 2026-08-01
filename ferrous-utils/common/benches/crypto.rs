// Benchmarks for Bitcoin cryptographic operations
//
// Tests SHA256 (ARM SHA2-accelerated where available, software elsewhere) and
// secp256k1 operations

use common::crypto::{
    bits_to_target, compute_merkle_root, double_sha256, hash160, target_to_bits,
    verify_ecdsa_signature,
};
use common::crypto::secp::{
    batch_verify_schnorr, verify_ecdsa_compact, verify_ecdsa_der, verify_schnorr,
    SchnorrVerifyItem,
};
use common::crypto::sha256::{
    detect_implementation, double_sha256 as hw_double_sha256, implementation_string,
    sha256 as hw_sha256, Sha256,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_sha256_hardware(c: &mut Criterion) {
    println!(
        "SHA256 implementation detected: {}",
        implementation_string()
    );

    let data_64 = [0u8; 64];
    let data_256 = [0u8; 256];
    let data_1024 = [0u8; 1024];

    c.bench_function("sha256_hw_64b", |b| {
        b.iter(|| hw_sha256(black_box(&data_64)))
    });

    c.bench_function("sha256_hw_256b", |b| {
        b.iter(|| hw_sha256(black_box(&data_256)))
    });

    c.bench_function("sha256_hw_1kb", |b| {
        b.iter(|| hw_sha256(black_box(&data_1024)))
    });

    // Benchmark incremental updates
    c.bench_function("sha256_hw_incremental_1kb", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            for chunk in data_1024.chunks(64) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });
}

fn bench_double_sha256_hardware(c: &mut Criterion) {
    let data_64 = [0u8; 64];
    let data_256 = [0u8; 256];

    c.bench_function("double_sha256_hw_64b", |b| {
        b.iter(|| hw_double_sha256(black_box(&data_64)))
    });

    c.bench_function("double_sha256_hw_256b", |b| {
        b.iter(|| hw_double_sha256(black_box(&data_256)))
    });

    // Compare old vs new implementation
    c.bench_function("double_sha256_old_64b", |b| {
        b.iter(|| double_sha256(black_box(&data_64)))
    });
}

fn bench_sha256_comparison(c: &mut Criterion) {
    // Compare hardware-accelerated vs library (bitcoin_hashes) implementation
    let mut group = c.benchmark_group("sha256_comparison");

    for size in [64, 256, 1024, 4096].iter() {
        let data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::new("hw", size), &data, |b, data| {
            b.iter(|| hw_sha256(black_box(data)))
        });

        group.bench_with_input(BenchmarkId::new("lib_double", size), &data, |b, data| {
            b.iter(|| double_sha256(black_box(data)))
        });
    }
    group.finish();
}

fn bench_verify_ecdsa_signature(c: &mut Criterion) {
    // Use dummy data for benchmarking (will fail verification, but tests the function)
    let sig_bytes = [0u8; 64]; // Compact signature format
    let pubkey_bytes = [
        0x02, // Compressed pubkey prefix
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ]; // Valid pubkey format (33 bytes)
    let msg_hash = [0u8; 32]; // Message hash

    c.bench_function("verify_ecdsa_signature_old", |b| {
        b.iter(|| {
            let _ = verify_ecdsa_signature(
                black_box(&sig_bytes),
                black_box(&pubkey_bytes),
                black_box(&msg_hash),
            );
        });
    });

    c.bench_function("verify_ecdsa_compact_new", |b| {
        b.iter(|| {
            let _ = verify_ecdsa_compact(
                black_box(&sig_bytes),
                black_box(&pubkey_bytes),
                black_box(&msg_hash),
            );
        });
    });
}

fn bench_schnorr_verification(c: &mut Criterion) {
    // BIP340 test vector #0
    let pubkey =
        hex::decode("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
            .unwrap();
    let msg = hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
        .unwrap();
    let sig = hex::decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
        .unwrap();

    c.bench_function("verify_schnorr_single", |b| {
        b.iter(|| {
            let _ = verify_schnorr(black_box(&sig), black_box(&pubkey), black_box(&msg));
        });
    });
}

fn bench_batch_schnorr(c: &mut Criterion) {
    // BIP340 test vector #0
    let pubkey =
        hex::decode("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
            .unwrap();
    let msg = hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
        .unwrap();
    let sig = hex::decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
        .unwrap();

    let mut group = c.benchmark_group("batch_schnorr");

    for batch_size in [1, 4, 16, 64].iter() {
        let items: Vec<SchnorrVerifyItem> = (0..*batch_size)
            .map(|_| SchnorrVerifyItem {
                sig: &sig,
                pubkey: &pubkey,
                msg_hash: &msg,
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &items,
            |b, items| {
                b.iter(|| batch_verify_schnorr(black_box(items)));
            },
        );
    }
    group.finish();
}

fn bench_double_sha256(c: &mut Criterion) {
    let data = b"This is test data for benchmarking double SHA-256 hash function";

    c.bench_function("double_sha256", |b| {
        b.iter(|| {
            let _ = double_sha256(black_box(data));
        });
    });

    // Benchmark with different input sizes
    let mut group = c.benchmark_group("double_sha256_sizes");
    for size in [32, 256, 1024, 4096].iter() {
        let data = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| double_sha256(black_box(data)));
        });
    }
    group.finish();
}

fn bench_hash160(c: &mut Criterion) {
    let data = b"This is test data for benchmarking Hash160 function";

    c.bench_function("hash160", |b| {
        b.iter(|| {
            let _ = hash160(black_box(data));
        });
    });

    // Benchmark with different input sizes
    let mut group = c.benchmark_group("hash160_sizes");
    for size in [32, 256, 1024].iter() {
        let data = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| hash160(black_box(data)));
        });
    }
    group.finish();
}

fn bench_compute_merkle_root(c: &mut Criterion) {
    // Benchmark with different numbers of transactions
    let mut group = c.benchmark_group("compute_merkle_root");

    for tx_count in [1, 2, 4, 8, 16, 32, 64, 128].iter() {
        let txids: Vec<[u8; 32]> = (0..*tx_count)
            .map(|i| {
                let mut txid = [0u8; 32];
                txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                txid
            })
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(tx_count), &txids, |b, txids| {
            b.iter(|| compute_merkle_root(black_box(txids)));
        });
    }
    group.finish();
}

fn bench_bits_to_target(c: &mut Criterion) {
    let test_bits = vec![
        0x1d00ffff, // Genesis block
        0x1b0404cb, // Block 1000
        0x1a05db8b, // Block 10000
        0x18009645, // Block 100000
    ];

    let mut group = c.benchmark_group("bits_to_target");
    for bits in test_bits {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("0x{:08x}", bits)),
            &bits,
            |b, bits| {
                b.iter(|| bits_to_target(black_box(*bits)));
            },
        );
    }
    group.finish();
}

fn bench_target_to_bits(c: &mut Criterion) {
    let test_targets = vec![
        bits_to_target(0x1d00ffff), // Genesis block
        bits_to_target(0x1b0404cb), // Block 1000
        bits_to_target(0x1a05db8b), // Block 10000
        bits_to_target(0x18009645), // Block 100000
    ];

    let mut group = c.benchmark_group("target_to_bits");
    for (i, target) in test_targets.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("target_{}", i)),
            target,
            |b, target| {
                b.iter(|| target_to_bits(black_box(*target)));
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sha256_hardware,
    bench_double_sha256_hardware,
    bench_sha256_comparison,
    bench_verify_ecdsa_signature,
    bench_schnorr_verification,
    bench_batch_schnorr,
    bench_double_sha256,
    bench_hash160,
    bench_compute_merkle_root,
    bench_bits_to_target,
    bench_target_to_bits
);
criterion_main!(benches);
