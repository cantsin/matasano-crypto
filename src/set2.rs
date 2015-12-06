
use std::{iter};
use rand::distributions::{IndependentSample, Range};
use rand::{thread_rng, Rng};

use conversion::*;
use crypto::*;
use util::*;

#[test]
fn challenge_9() {
    let sample = "YELLOW SUBMARINE";
    let result = pad_pkcs7(&string_to_raw(sample), 20);
    assert!(raw_to_string(&result) == "YELLOW SUBMARINE\u{04}\u{04}\u{04}\u{04}")
}

#[test]
fn decrypt_encrypt_ecb() {
    let key = "YELLOW SUBMARINE";
    let sample = "a test a testing";
    let encrypted = encrypt_aes_ecb(&string_to_raw(sample), key);
    let decrypted = raw_to_string(&decrypt_aes_ecb(&encrypted, key));
    assert!(decrypted == sample);
}

#[test]
fn decrypt_encrypt_cbc() {
    let key = "YELLOW SUBMARINE";
    let sample = "a test a testing";
    let iv: Vec<u8> = iter::repeat(0).take(16).collect();
    let encrypted = encrypt_aes_cbc(&iv, &string_to_raw(sample), key);
    let decrypted = raw_to_string(&decrypt_aes_cbc(&iv, &encrypted, key));
    assert!(decrypted == sample);
}

#[test]
fn challenge_10() {
    let Base64(block) = read_base64_file("data/10.txt");
    let key = "YELLOW SUBMARINE";
    let iv: Vec<u8> = iter::repeat(0).take(16).collect();
    let result = decrypt_aes_cbc(&iv, &block, key);
    let decrypted = raw_to_string(&result);
    // "somewhat" intelligible
    let snippet = "I\'m back and I\'ml \nA rockin\' on he fly";
    assert!(&decrypted[..snippet.len()] == snippet);
}

#[test]
fn challenge_11() {
    let mut rng = thread_rng();
    for _ in 0..100 {
        let n = Range::new(64, 256).ind_sample(&mut rng);
        let plaintext: Vec<u8> = iter::repeat('x' as u8).take(n).collect();
        let (secret_mode, result) = encryption_oracle(&plaintext);
        let mode = guess_mode(&result);
        assert!(mode == secret_mode);
    }
}

#[test]
fn challenge_12() {
    let mystery_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let Base64(mystery) = string_to_base64(&mystery_string);
    let random_key = "testing testing ";
    let oracle = create_oracle(&mystery, &random_key);
    let result = decrypt_ecb_simple(oracle);
    assert!(result == raw_to_string(&mystery));
}
