
use quickcheck::{quickcheck, Gen, Arbitrary};
use std::io::prelude::*;
use std::fs::File;
use std::cmp::Ordering;
use std::collections::BTreeMap;

use util::*;

#[test]
fn challenge_1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let result = printable64(&raw_to_base64(&hex_to_raw(input)));
    assert!(result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test]
fn challenge_2() {
    let x = hex_to_raw("1c0111001f010100061a024b53535009181c");
    let y = hex_to_raw("686974207468652062756c6c277320657965");
    let result = printable16(&xor(&x, &y));
    assert!(result == "746865206B696420646F6E277420706C6179");
}

#[test]
fn challenge_3() {
    let encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let v = hex_to_raw(encrypted);

    // TODO refactor
    let keys = ascii_single_keys();
    let mut map = BTreeMap::new();

    for i in keys {
        let result = raw_to_ascii(&xor_one(&v, i as u8));
        let p = english_probability(&result);
        map.insert(p, result.clone());
    }

    let best_match = map.iter().rev().next().unwrap();


    assert!(&best_match.1[..] == "Cooking MC's like a pound of bacon");
}

#[test]
fn challenge_4() {
    let mut f = File::open("data/4.txt").unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);

    // TODO refactor
    let keys = ascii_single_keys();
    let mut map = BTreeMap::new();

    for line in s.split('\n') {
        let v = hex_to_raw(&line);
        for i in keys.clone() {
            let result = raw_to_ascii(&xor_one(&v, i as u8));
            let p = english_probability(&result);
            map.insert(p, result.clone());
        }
    }

    let best_match = map.iter().rev().next().unwrap();
    assert!(&best_match.1[..] == "Now that the party is jumping\n");
}

#[test]
fn challenge_5() {
    let original = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = "ICE";

    let o = ascii_to_raw(&original);
    let result = xor_key(&o, &key);
    let encrypted = printable16(&result);

    assert!(encrypted == "0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26226324272765272A282B2F20430A652E2C652A3124333A653E2B2027630C692B20283165286326302E27282F")
}

#[test]
fn hamming_distance() {
    assert!(hamming("this is a test", "wokka wokka!!!") == 37);
}

#[test]
fn transpose_matrix() {
    let v: Vec<Vec<u8>> = vec![
        vec![1,2,3,4],
        vec![5,6,7,8],
        vec![9,10,11,12],
        vec![13,14,15,16]];
    let v2 = transpose(&v);
    assert!(v2 == vec![vec![1,5,9,13],
                       vec![2,6,10,14],
                       vec![3,7,11,15],
                       vec![4,8,12,16]])
}

#[test]
fn challenge_6() {
    let mut f = File::open("data/6.txt").unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    s = s.split('\n').flat_map(|x| x.chars()).collect();

    // TODO: refactor into break-repeating-key-xor
    // params: block, keysize range

    let mut map = BTreeMap::new();

    for keysize in 2..40 {
        let first = &s[..keysize];
        let second = &s[keysize..keysize*2];
        let edit_dist = hamming(&first, &second);
        let norm = (edit_dist as f64 / keysize as f64) * 100000.0;
        map.insert(norm as usize, keysize);
    }

    print!("{:?}\n", map);

    // try the smallest 2-3 keysizes
    let keysizes: Vec<usize> = map.iter().take(3).map(|k| *k.1).collect();
    for best_keysize in keysizes {
        let chunks: Vec<Vec<u8>> = s.as_bytes().chunks(best_keysize).map(|c| {
            c.iter().cloned().collect()
        }).collect();
        let t = transpose(&chunks);
    }

    assert!(false);
}

#[derive(Clone, Debug)]
struct Text {
    value: String
}

impl Arbitrary for Text {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut len = u16::arbitrary(g);
        let mut s = String::with_capacity(len as usize);
        len += len % 2; // must be even
        for _ in 0..len {
            let i = usize::arbitrary(g);
            let i = i % HEX_ALPHABET.len();
            s.push(HEX_ALPHABET.as_bytes()[i] as char);
        }
        Text { value: s }
    }
}

#[test]
fn hex_conversion_idempotent() {
    fn equality_after_applying_twice(t: Text) -> bool {
        t.value == printable16(&hex_to_raw(&t.value[..]))
    }
    quickcheck(equality_after_applying_twice as fn(Text) -> bool);
}
