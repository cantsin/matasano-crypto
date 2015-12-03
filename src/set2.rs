
use conversion::*;
use util::*;
use std::{iter};
use std::io::prelude::*;
use std::fs::File;

#[test]
fn challenge_1() {
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
fn challenge_2() {
    let mut f = File::open("data/10.txt").unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let raw: String = s.split('\n').flat_map(|x| x.chars()).collect();
    let Base64(block) = string_to_base64(&raw);

    let key = "YELLOW SUBMARINE";
    let iv: Vec<u8> = iter::repeat(0).take(16).collect();
    let result = decrypt_aes_cbc(&iv, &block, key);
    let decrypted = raw_to_string(&result);
    // "somewhat" intelligible
    let snippet = "I\'m back and I\'ml \nA rockin\' on he fly";
    assert!(&decrypted[..snippet.len()] == snippet);
}
