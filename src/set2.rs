
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
    let random_key = raw_to_string(&random_aes());
    let oracle = create_simple_oracle(&mystery, &random_key);
    let result = decrypt_ecb(oracle);
    // we may be decrypting past the known string due to the
    // ciphertext being rounded up to the nearest block size.
    assert!(result[..mystery.len()] == raw_to_string(&mystery));
}

#[test]
fn test_key_value() {
    let query = "foo=bar&baz=qux&zap=zazzle";
    let desired = vec![("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")];
    let result: Vec<(String, String)> = desired.iter().map(|&(k, v)| {
        (k.to_string(),
         v.to_string())
    }).collect();
    assert!(key_value(query) == result);
}

#[test]
fn test_profile_for() {
    let encoding = "email=foo@bar.com&uid=10&role=user";
    assert!(profile_for("foo@bar.com") == encoding);
}

#[test]
fn test_profile_for_is_sane() {
    let encoding = "email=foo@bar.comroleadmin&uid=10&role=user";
    assert!(profile_for("foo@bar.com&role=admin") == encoding);
}

#[test]
fn create_role_admin() {
    let padded = pad_pkcs7(&string_to_raw("admin"), 16);
    let profile = "not-a-suspicious-user@foo.com";

    // construct a string such that we cut off "...&role=" in its own block
    let (split1, split2) = profile.split_at(10);
    let mut modified_profile = vec![];
    modified_profile.extend(split1.bytes());
    modified_profile.extend(&padded);
    modified_profile.extend(split2.bytes());

    let new_profile = profile_for(&raw_to_string(&modified_profile));
    let (key, encrypted) = encrypt_profile(&new_profile);

    // split the blocks up.
    let first = &encrypted[..16];
    let admin = &encrypted[16..32];
    let second = &encrypted[32..64];

    // re-splice.
    let mut result = vec![];
    result.extend(first);
    result.extend(second);
    result.extend(admin);

    let new_user = decrypt_profile(&result, &key);

    let string_tuple = |k: &str, v: &str| (k.to_string(), v.to_string());
    assert!(new_user[0] == string_tuple("email", "not-a-suspicious-user@foo.com"));
    assert!(new_user[1] == string_tuple("uid", "10"));
    assert!(new_user[2] == string_tuple("role", "admin"));
}

#[test]
fn challenge_14() {
    let mystery_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let Base64(mystery) = string_to_base64(&mystery_string);
    let random_key = raw_to_string(&random_aes());
    let oracle = create_harder_oracle(&mystery, &random_key);
    let result = decrypt_ecb(oracle);
    // we may be decrypting past the known string due to the
    // ciphertext being rounded up to the nearest block size.
    assert!(result[..mystery.len()] == raw_to_string(&mystery));
}

#[test]
fn challenge_15() {
    assert!(strip_padding("ICE ICE BABY\x04\x04\x04\x04") == Some("ICE ICE BABY".to_string()));
    assert!(strip_padding("ICE ICE BABY\x05\x05\x05\x05") == None);
    assert!(strip_padding("ICE ICE BABY\x01\x02\x03\x04") == None);
}
