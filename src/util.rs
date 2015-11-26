#![allow(dead_code)]

use std::*;
use std::collections::{HashMap};

pub const ALPHABET: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const HEX_ALPHABET: &'static str = "0123456789ABCDEF";
pub const BASE64_ALPHABET: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn printable64(v: &Vec<u8>) -> String {
    if v.len() == 0 {
        return "".to_string();
    }
    v.iter().map(|&elem| {
        let mut x: u32 = elem as u32;
        let mut v = String::new();
        while x > 0 {
            v.push(BASE64_ALPHABET.char_at((x % 64) as usize));
            x /= 64;
        }
        v.chars().rev().collect::<String>()
    }).collect()
}

pub fn printable16(v: &Vec<u8>) -> String {
    if v.len() == 0 {
        return "".to_string();
    }
    let result: String = v.iter().map(|&elem| {
        let mut x: u32 = elem as u32;
        let mut v = String::new();
        while x > 0 {
            v.push(HEX_ALPHABET.char_at((x % 16) as usize));
            x /= 16;
        }

        // pad out hexcodes
        let original = elem as u32;
        if original < 16 {
            v.push('0');
        }
        if original == 0 {
            v.push('0');
        }

        v.chars().rev().collect::<String>()
    }).collect();

    // strip leading '0' if extant
    if result.char_at(0) == '0' {
        return result[1..].to_string();
    }
    return result.clone();
}

fn hex_to_int(c: char) -> u32 {
    assert!(c.is_digit(16));
    c.to_digit(16).unwrap()
}

pub fn ascii_single_keys() -> Vec<u8> {
    ALPHABET.chars().map(|c| c as u8).collect()
}

pub fn raw_to_ascii(v: &Vec<u8>) -> String {
    v.iter().map(|&x| x as char).collect()
}

pub fn ascii_to_raw(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

pub fn hex_to_raw(s: &str) -> Vec<u8> {
    let padded = if (s.len() % 2) == 1 {
        format!("0{}", s)
    } else {
        s.to_string()
    };
    padded.as_bytes().chunks(2).map(|elem| {
        let first = elem[0];
        let second = elem[1];
        let n = 16 * hex_to_int(first as char) + hex_to_int(second as char);
        n as u8
    }).collect()
}

pub fn raw_to_base64(v: &Vec<u8>) -> Vec<u8> {
    v.chunks(3).flat_map(|elem| {
        let s1 = elem[0] >> 2;
        let s2 = ((elem[0] & 0x3) << 4) | ((elem[1] & 0xf0) >> 4);
        let s3 = ((elem[1] & 0x0f) << 2) | ((elem[2] & 0xc0) >> 6);
        let s4 = elem[2] & 0x3f;
        vec![s1, s2, s3, s4]
    }).collect()
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
