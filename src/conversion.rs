
use std::io::prelude::*;
use std::fs::File;

pub const ALPHABET: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !\"#$%&'()*+,-./:;<=>?@{|}~";
pub const HEX_ALPHABET: &'static str = "0123456789ABCDEF";
pub const BASE64_ALPHABET: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub struct Base64(pub Vec<u8>);
pub struct Hex(pub Vec<u8>);

pub fn ascii_single_keys() -> Vec<u8> {
    ALPHABET.chars().map(|c| c as u8).collect()
}

fn hex_to_int(c: char) -> u32 {
    assert!(c.is_digit(16));
    c.to_digit(16).unwrap()
}

pub fn raw_to_string(v: &Vec<u8>) -> String {
    v.iter().map(|&x| x as char).collect()
}

pub fn string_to_raw(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

pub fn string_to_hex(s: &str) -> Hex {
    let padded = if (s.len() % 2) == 1 {
        format!("0{}", s)
    } else {
        s.to_string()
    };
    let result = padded.as_bytes().chunks(2).map(|elem| {
        let first = elem[0];
        let second = elem[1];
        let n = 16 * hex_to_int(first as char) + hex_to_int(second as char);
        n as u8
    }).collect();
    Hex(result)
}

pub fn string_to_base64(s: &str) -> Base64 {
    assert!((s.len() % 4) == 0);
    let result = s.as_bytes().chunks(4).flat_map(|elem| {
        let e0 = BASE64_ALPHABET.find(elem[0] as char).unwrap() as u8;
        let e1 = BASE64_ALPHABET.find(elem[1] as char).unwrap() as u8;
        let s1 = (e0 << 2) | (e1 >> 4);
        if elem[2] != b'=' {
            let e2 = BASE64_ALPHABET.find(elem[2] as char).unwrap() as u8;
            let s2 = (e1 << 4) | (e2 >> 2);
            if elem[3] != b'=' {
                let e3 = BASE64_ALPHABET.find(elem[3] as char).unwrap() as u8;
                let s3 = (e2 << 6) | e3;
                vec![s1, s2, s3]
            } else {
                vec![s1, s2]
            }
        } else {
            vec![s1]
        }
    }).collect();
    Base64(result)
}

pub fn hex_to_string(raw: Hex) -> String {
    let Hex(v) = raw;
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
    result
}

pub fn raw_to_base64(v: &Vec<u8>) -> Base64 {
    let result = v.chunks(3).flat_map(|elem| {
        let s1 = elem[0] >> 2;
        let s2 = ((elem[0] & 0x3) << 4) | ((elem[1] & 0xf0) >> 4);
        let s3 = ((elem[1] & 0x0f) << 2) | ((elem[2] & 0xc0) >> 6);
        let s4 = elem[2] & 0x3f;
        vec![s1, s2, s3, s4]
    }).collect();
    Base64(result)
}

pub fn base64_to_string(raw: Base64) -> String {
    let Base64(v) = raw;
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

pub fn read_base64_file(filename: &str) -> Base64 {
    let mut f = File::open(filename).unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let raw: String = s.split('\n').flat_map(|x| x.chars()).collect();
    string_to_base64(&raw)
}

pub fn read_hexlines_file(filename: &str) -> Vec<Vec<u8>> {
    let mut f = File::open(filename).unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    s.split('\n').map(|l| {
        let Hex(v) = string_to_hex(&l);
        v
    }).collect()
}
