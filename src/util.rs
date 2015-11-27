#![allow(dead_code)]

use std::*;
use std::collections::{HashMap, BTreeMap};
use conversion::*;

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
    p += test_against(&histogram, n, ' ', 0.10, 20);
    p += test_against(&histogram, n, 'e', 0.12, 20);
    p += test_against(&histogram, n, 't', 0.09, 18);
    p += test_against(&histogram, n, 'a', 0.08, 15);
    p += test_against(&histogram, n, 'o', 0.07, 12);
    p += test_against(&histogram, n, 'i', 0.07, 10);
    p
}

// 'a', 8.167
// 'b', 1.492
// 'c', 2.782
// 'd', 4.253
// 'e', 12.702
// 'f', 2.228
// 'g', 2.015
// 'h', 6.094
// 'i', 6.966
// 'j', 0.153
// 'k', 0.772
// 'l', 4.025
// 'm', 2.406
// 'n', 6.749
// 'o', 7.507
// 'p', 1.929
// 'q', 0.095
// 'r', 5.987
// 's', 6.327
// 't', 9.056
// 'u', 2.758
// 'v', 0.978
// 'w', 2.361
// 'x', 0.150
// 'y', 1.974
// 'z', 0.074

pub fn hamming(s1: &str, s2: &str) -> usize {
    assert!(s1.len() == s2.len());
    let x1 = string_to_raw(s1);
    let x2 = string_to_raw(s2);
    let result = xor(&x1, &x2);
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
