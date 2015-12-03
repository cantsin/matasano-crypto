#![allow(dead_code)]

use std::{iter, ops};
use std::collections::{HashMap, BTreeMap};
use openssl::crypto::symm::{encrypt, decrypt, Type};
use rand::distributions::{IndependentSample, Range};
use rand::{thread_rng, Rng};

use conversion::*;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Mode {
    ECB,
    CBC
}

pub fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    v1.iter().zip(v2).map(|(x, y)| x ^ y).collect()
}

pub fn xor_one(v: &Vec<u8>, val: u8) -> Vec<u8> {
    v.iter().map(|x| x ^ val).collect()
}

pub fn xor_key(v: &Vec<u8>, key: &str) -> Vec<u8> {
    let k: String = iter::repeat(key).take(v.len()).collect();
    let v2 = k.chars().map(|x: char| x as u8).collect();
    xor(v, &v2)
}

// single-byte xor
pub fn sbx(v: &Vec<u8>) -> BTreeMap<i64, String> {
    let keys = ascii_single_keys();
    let mut map = BTreeMap::<i64, String>::new();
    for i in keys {
        let result = raw_to_string(&xor_one(&v, i as u8));
        let p = english_probability(&result);
        map.insert(-p, result.clone()); // flip so that better results come first
    }
    map
}

// detect single-byte xor
pub fn detect_sbx(tests: &Vec<Vec<u8>>) -> BTreeMap<i64, String> {
    let keys = ascii_single_keys();
    let mut map = BTreeMap::new();

    for test in tests {
        for i in keys.clone() {
            let result = raw_to_string(&xor_one(&test, i as u8));
            let p = english_probability(&result);
            map.insert(-p, result.clone()); // flip so that better results come first
        }
    }
    map
}

pub fn is_printable(c: char) -> bool {
    let v = c as u8;
    v >= 32 && v < 127
}

fn test_against(map: &HashMap<char, usize>, length: usize, c: char, threshold: f64, weight: usize) -> i64 {
    let n = length as f64;
    if let Some(&occurence) = map.get(&c) {
        let freq = (occurence as f64) / n;
        if freq > threshold {
            weight as i64
        } else {
            (weight as f64 * (freq / threshold)) as i64
        }
    }
    else {
        0
    }
}

pub fn english_probability(s: &str) -> i64 {
    let mut p = 0;
    let result: String = s.chars().filter(|&c| is_printable(c)).collect();
    p += (result.len() as i64) * 2;
    let mut histogram = HashMap::new();
    for c in s.chars() {
        let counter = histogram.entry(c).or_insert(0);
        *counter += 1;
    }
    let n = s.len();
    p += test_against(&histogram, n, ' ', 0.130, 20);
    p += test_against(&histogram, n, 'e', 0.127, 20);
    p += test_against(&histogram, n, 't', 0.091, 18);
    p += test_against(&histogram, n, 'a', 0.081, 15);
    p += test_against(&histogram, n, 'o', 0.075, 12);
    p += test_against(&histogram, n, 'i', 0.070, 10);
    p += test_against(&histogram, n, 'n', 0.067, 9);
    p += test_against(&histogram, n, 's', 0.063, 8);
    p += test_against(&histogram, n, 'h', 0.061, 7);
    p += test_against(&histogram, n, 'r', 0.060, 6);
    p += test_against(&histogram, n, 'd', 0.043, 5);
    p += test_against(&histogram, n, 'l', 0.040, 4);
    // 'c', 0.02782
    // 'u', 0.02758
    // 'm', 0.02406
    // 'w', 0.02361
    // 'f', 0.02228
    // 'g', 0.02015
    // 'y', 0.01974
    // 'p', 0.01929
    // 'b', 0.01492
    // 'v', 0.00978
    // 'k', 0.00772
    // 'j', 0.00153
    // 'x', 0.00150
    // 'q', 0.00095
    // 'z', 0.00074
    p
}

pub fn hamming(v1: &Vec<u8>, v2: &Vec<u8>) -> usize {
    assert!(v1.len() == v2.len());
    let result = xor(&v1, &v2);
    result.iter().fold(0, |accum, &x| {
        let mut n = 0;
        let mut elem = x;
        while elem > 0 {
            if (elem & 1) == 1 {
                n += 1;
            }
            elem >>= 1;
        }
        accum + n
    })
}

pub fn transpose(chunks: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let len = chunks.iter().map(|c| c.len()).max().unwrap();
    let mut vecs: Vec<Vec<u8>> = (0..len).map(|_| Vec::new()).collect();
    for c1 in chunks.iter() {
        for (j, &c2) in c1.iter().enumerate() {
            vecs[j].push(c2);
        }
    }
    vecs
}

pub fn likely_keysizes(block: &Vec<u8>, range: ops::Range<usize>) -> Vec<usize> {

    let mut map = BTreeMap::new();

    for keysize in range {
        // take four keysize blocks ...
        let first: &Vec<u8> = &block[..keysize].to_vec();
        let second: &Vec<u8> = &block[keysize..keysize*2].to_vec();
        let third: &Vec<u8> = &block[keysize*2..keysize*3].to_vec();
        let fourth: &Vec<u8> = &block[keysize*3..keysize*4].to_vec();

        // ... get the hamming distance for each ...
        let edit_dist1 = hamming(first, second) as f64 / keysize as f64;
        let edit_dist2 = hamming(first, third) as f64 / keysize as f64;
        let edit_dist3 = hamming(first, fourth) as f64 / keysize as f64;
        let edit_dist4 = hamming(second, third) as f64 / keysize as f64;
        let edit_dist5 = hamming(second, fourth) as f64 / keysize as f64;
        let edit_dist6 = hamming(third, fourth) as f64 / keysize as f64;

        // ... and average the distances.
        let norm = (edit_dist1 + edit_dist2 + edit_dist3 +
                    edit_dist4 + edit_dist5 + edit_dist6) / 6.0 * 100000.0;

        map.insert(norm as usize, keysize);
    }

    map.values().cloned().collect()
}

pub fn break_repeating_key_xor(block: &Vec<u8>, lengths: &Vec<usize>) -> Vec<String> {

    let mut solutions = vec![];
    let keys = ascii_single_keys();

    for &length in lengths {

        // transpose the blocks so we can xor each block with an individual key
        let chunks: Vec<Vec<u8>> = block.chunks(length).map(|c| {
            c.iter().cloned().collect()
        }).collect();
        let transposed = transpose(&chunks);

        // get the best matching single key per block
        let mut block_key = vec![];
        for block in transposed {
            let mut map = BTreeMap::new();
            for key in keys.clone() {
                let result = raw_to_string(&xor_one(&block, key as u8));
                let p = english_probability(&result);
                map.insert(-p, key);
            }
            let best_match = map.iter().next().unwrap();
            block_key.push(*best_match.1);
        }
        let s: String = block_key.iter().map(|&x| x as char).collect();
        solutions.push(s);
    }

    solutions

}
pub fn decrypt_aes_ecb(v: &Vec<u8>, key: &str) -> Vec<u8> {
    let k = string_to_raw(key);
    decrypt(Type::AES_128_ECB, &k, &[], &v)
}

pub fn encrypt_aes_ecb(v: &Vec<u8>, key: &str) -> Vec<u8> {
    let k = string_to_raw(key);
    encrypt(Type::AES_128_ECB, &k, &[], &v)
}

pub fn decrypt_aes_cbc(iv: &Vec<u8>, block: &Vec<u8>, key: &str) -> Vec<u8> {
    let mut previous = iv.clone();
    let mut result: Vec<u8> = vec![];
    let chunks: Vec<Vec<u8>> = block.chunks(key.len() * 2).map(|c| {
        c.iter().cloned().collect()
    }).collect();
    for ciphertext in chunks {
        let block = decrypt_aes_ecb(&ciphertext, key);
        let mut plaintext = xor(&previous, &block);
        result.append(&mut plaintext);
        let copy = &mut ciphertext.clone();
        previous = copy.split_off(key.len()).clone();
    }
    result
}

pub fn encrypt_aes_cbc(iv: &Vec<u8>, block: &Vec<u8>, key: &str) -> Vec<u8> {
    let mut previous = iv.clone();
    let mut result: Vec<u8> = vec![];
    let chunks: Vec<Vec<u8>> = block.chunks(key.len()).map(|c| {
        c.iter().cloned().collect()
    }).collect();
    for plaintext in chunks {
        let block = xor(&previous, &plaintext);
        let mut ciphertext = encrypt_aes_ecb(&block, key);
        previous = ciphertext.clone();
        result.append(&mut ciphertext);
    }
    result
}

pub fn test_for_aes_ecb(tests: &Vec<Vec<u8>>) -> Vec<u8> {

    let mut highest = 0;
    let mut best_match = vec![];

    for test in tests {
        if test.len() == 0 {
            continue;
        }

        // do we have any repeating 16 byte patterns?
        let mut histogram = HashMap::new();
        let patterns: Vec<&[u8]> = test.chunks(16).collect();
        for pattern in patterns {
            let counter = histogram.entry(pattern).or_insert(0);
            *counter += 1;
        }

        let max = *histogram.values().max().unwrap();
        if max > highest {
            highest = max;
            best_match = test.clone();
        }
    }

    best_match
}

pub fn pad_pkcs7(v: &Vec<u8>, n: usize) -> Vec<u8> {
    assert!(n < 256);
    let l = n - v.len();
    let mut result = v.clone();
    let mut suffix: Vec<u8> = iter::repeat(l as u8).take(l).collect();
    result.append(&mut suffix);
    result
}

pub fn random_aes() -> Vec<u8> {
    let mut rng = thread_rng();
    (0..).take(16).map(|_| rng.gen::<u8>()).collect()
}

pub fn encryption_oracle(input: &Vec<u8>) -> (Mode, Vec<u8>) {
    let mut rng = thread_rng();
    // append 5-10 bytes before and after
    let between = Range::new(5, 11);
    let prefix_length = between.ind_sample(&mut rng);
    let suffix_length = between.ind_sample(&mut rng);
    let prefix: Vec<u8> = (0..).take(prefix_length).map(|_| rng.gen::<u8>()).collect();
    let suffix: Vec<u8> = (0..).take(suffix_length).map(|_| rng.gen::<u8>()).collect();

    let mut result: Vec<u8> = vec![];
    result.extend(prefix);
    result.extend(input.clone());
    result.extend(suffix);

    // choose a mode to encrypt
    let key = raw_to_string(&random_aes());
    if rng.gen() {
        (Mode::ECB, encrypt_aes_ecb(&result, &key))
    } else {
        let iv = random_aes();
        (Mode::CBC, encrypt_aes_cbc(&iv, &result, &key))
    }
}

pub fn guess_mode(v: &Vec<u8>) -> Mode {
    Mode::CBC
}
