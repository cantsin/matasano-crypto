
use std::{iter, ops};
use std::collections::{HashMap, BTreeMap};
use openssl::crypto::symm::{encrypt, decrypt, Type};
use rand::distributions::{IndependentSample, Range};
use rand::{thread_rng, Rng};

use conversion::*;
use util::*;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Mode {
    ECB,
    CBC
}

pub fn single_byte_xor(v: &Vec<u8>) -> BTreeMap<i64, String> {
    let keys = ascii_single_keys();
    let mut map = BTreeMap::<i64, String>::new();
    for i in keys {
        let result = raw_to_string(&xor_one(&v, i as u8));
        let p = english_probability(&result);
        map.insert(-p, result.clone()); // flip so that better results come first
    }
    map
}

pub fn detect_single_byte_xor(tests: &Vec<Vec<u8>>) -> BTreeMap<i64, String> {
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

pub fn test_for_aes_ecb(tests: &Vec<Vec<u8>>) -> Option<Vec<u8>> {

    let mut highest = 2; // err on the side of caution
    let mut best_match = None;

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
            best_match = Some(test.clone());
        }
    }

    best_match
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
    if v.len() < 64 {
        panic!("Not enough information provided.");
    }

    // look for repeating sub-patterns
    let tests: Vec<Vec<u8>> = (0..16).map(|n| v[n..].to_vec()).collect();
    match test_for_aes_ecb(&tests) {
        Some(_) => Mode::ECB,
        None => Mode::CBC
    }
}

pub type Oracle = Fn(&Vec<u8>) -> Vec<u8>;

pub fn create_oracle(_mystery: &Vec<u8>, _key: &str) -> Box<Oracle> {
    let mystery = _mystery.clone();
    let key = _key.to_string().clone();
    Box::new(move |input: &Vec<u8>| {
        let mut result: Vec<u8> = vec![];
        result.extend(input.clone());
        result.extend(mystery.clone());
        encrypt_aes_ecb(&result, &key)
    })
}

pub fn decrypt_ecb_simple(oracle: Box<Oracle>) -> String {

    let x = iter::repeat('x' as u8);

    // discover the cipher block size.
    let mut sizes = vec![];
    for size in 0..32 {
        let test: Vec<u8> = x.clone().take(size).collect();
        let result = oracle(&test);
        sizes.push(result.len());
    }
    let block_size = gcd_array(&sizes);

    // make sure we do indeed have an ecb oracle on our hands.
    let test: Vec<u8> = x.clone().take(128).collect();
    let mode = guess_mode(&oracle(&test));
    assert!(mode == Mode::ECB);

    // decrypt.
    let mut decrypted = vec![];
    for i in 0.. {

        // which block are we looking at?
        let b = i / block_size;
        let n = ((b + 1) * block_size) - i - 1;

        let mut prefix: Vec<u8> = x.clone().take(n as usize).collect();
        let result = &oracle(&prefix);
        let range = block_size*b..block_size*(b + 1);
        let matching = result[range.clone()].to_vec();
        prefix.extend(decrypted.clone());

        // construct the attack dictionary.
        let mut attack = HashMap::new();
        for ch in 0..255u8 {
            let mut test = prefix.clone();
            test.push(ch);
            let result = &oracle(&test);
            let block = result[range.clone()].to_vec();
            attack.insert(block, ch);
        }

        // keep going until we can't match any more.
        let block = attack.get(&matching.clone());
        match block {
            Some(ch) => decrypted.push(ch.clone()),
            _ => break
        }
    }

    return raw_to_string(&decrypted);
}
