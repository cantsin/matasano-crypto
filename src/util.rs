#![allow(dead_code)]

use std::{iter};
use std::collections::{HashMap};

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

pub fn is_printable(c: char) -> bool {
    let v = c as u8;
    v >= 32 && v < 127
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

pub fn pad_pkcs7(v: &Vec<u8>, n: usize) -> Vec<u8> {
    assert!(n < 256);
    let l = n - v.len();
    let mut result = v.clone();
    let mut suffix: Vec<u8> = iter::repeat(l as u8).take(l).collect();
    result.append(&mut suffix);
    result
}
