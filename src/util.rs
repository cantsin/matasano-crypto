#![allow(dead_code)]

pub const HEX_ALPHABET: &'static str = "0123456789ABCDEF";
pub const BASE64_ALPHABET: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn printable(v: &Vec<u8>, radix: u32) -> String {
    let mut s = String::new();

    assert!(radix==16 || radix==64);
    let lookup = match radix {
        16 => HEX_ALPHABET,
        64 => BASE64_ALPHABET,
        _ => panic!("unreachable")
    };

    for &elem in v.iter() {
        let mut x: u32 = elem as u32;
        let mut v = String::new();
        while x > 0 {
            v.push(lookup.char_at((x % radix) as usize));
            x /= radix;
        }

        // pad out hexcodes
        if radix == 16 {
            let original = elem as u32;
            if original < radix {
                v.push('0');
            }
            if original == 0 {
                v.push('0');
            }
        }

        let result = v.chars().rev().collect::<String>();
        s.push_str(result.as_str());
    }

    // strip leading '0' if extant
    if s.char_at(0) == '0' {
        return s[1..].to_string();
    }
    return s.clone();
}

fn hex_to_int(c: char) -> u32 {
    assert!(c.is_digit(16));
    return c.to_digit(16).unwrap();
}

pub fn hex_to_raw(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let hex = if (s.len() % 2) == 1 {
        format!("0{}", s)
    } else {
        s.to_string()
    };
    for elem in hex.as_bytes().chunks(2) {
        let first = elem[0];
        let second = elem[1];
        let n = 16 * hex_to_int(first as char) + hex_to_int(second as char);
        result.push(n as u8);
    }
    return result;
}

pub fn raw_to_base64(v: &Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();
    for elem in v.chunks(3) {
        let s1 = elem[0] >> 2;
        let s2 = ((elem[0] & 0x3) << 4) | ((elem[1] & 0xf0) >> 4);
        let s3 = ((elem[1] & 0x0f) << 2) | ((elem[2] & 0xc0) >> 6);
        let s4 = elem[2] & 0x3f;
        result.append(&mut vec![s1, s2, s3, s4]);
    }
    return result;
}
