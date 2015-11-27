
use quickcheck::{quickcheck, Gen, Arbitrary};
use std::io::prelude::*;
use std::fs::File;

use conversion::*;
use util::*;

#[test]
fn challenge_1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let Hex(v) = string_to_hex(input);
    let result = base64_to_string(raw_to_base64(&v));
    assert!(result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test]
fn challenge_2() {
    let Hex(x) = string_to_hex("1c0111001f010100061a024b53535009181c");
    let Hex(y) = string_to_hex("686974207468652062756c6c277320657965");
    let result = hex_to_string(Hex(xor(&x, &y)));
    assert!(result == "746865206B696420646F6E277420706C6179");
}

#[test]
fn challenge_3() {
    let encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let Hex(v) = string_to_hex(encrypted);
    let result = sbx(&v);
    let best_match = result.iter().next().unwrap();
    assert!(&best_match.1[..] == "Cooking MC's like a pound of bacon");
}

#[test]
fn challenge_4() {
    let mut f = File::open("data/4.txt").unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let tests = s.split('\n').map(|l| {
        let Hex(v) = string_to_hex(&l);
        v
    }).collect();
    let result = detect_sbx(&tests);
    let best_match = result.iter().next().unwrap();
    assert!(&best_match.1[..] == "Now that the party is jumping\n");
}

#[test]
fn challenge_5() {
    let original = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = "ICE";

    let o = string_to_raw(&original);
    let result = xor_key(&o, &key);
    let encrypted = hex_to_string(Hex(result));

    assert!(encrypted == "0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26226324272765272A282B2F20430A652E2C652A3124333A653E2B2027630C692B20283165286326302E27282F")
}

#[test]
fn hamming_distance() {
    let phrase1 = string_to_raw("this is a test");
    let phrase2 = string_to_raw("wokka wokka!!!");
    assert!(hamming(&phrase1, &phrase2) == 37);
}

#[test]
fn transpose_matrix() {
    let v: Vec<Vec<u8>> = vec![
        vec![1,2,3],
        vec![5,6,7],
        vec![9,10,11],
        vec![13,14,15]];
    let v2 = transpose(&v);
    assert!(v2 == vec![vec![1,5,9,13],
                       vec![2,6,10,14],
                       vec![3,7,11,15]])
}

#[test]
fn base64_decode() {
    let Base64(x1) = string_to_base64("TWFu");
    let result = raw_to_string(&x1);
    assert!(result == "Man");

    let Base64(x2) = string_to_base64("YW55IGNhcm5hbCBwbGVhc3VyZS4=");
    let result = raw_to_string(&x2);
    assert!(result == "any carnal pleasure.");

    let Base64(x3) = string_to_base64("YW55IGNhcm5hbCBwbGVhcw==");
    let result = raw_to_string(&x3);
    assert!(result == "any carnal pleas");
}

#[test]
fn challenge_6() {
    let mut f = File::open("data/6.txt").unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let raw: String = s.split('\n').flat_map(|x| x.chars()).collect();
    let Base64(block) = string_to_base64(&raw);

    let keysizes = likely_keysizes(&block, 2..41);
    let keys = break_repeating_key_xor(&block, &keysizes[..3].to_vec());
    let ref key = keys[0];
    assert!(key == "Terminator X: Bring the noise");

    let result = xor_key(&block, &key);
    let decrypted = raw_to_string(&result);
    let snippet = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy.";
    assert!(&decrypted[..snippet.len()] == snippet);
}

#[test]
fn challenge_7() {
    let mut f = File::open("data/7.txt").unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let raw: String = s.split('\n').flat_map(|x| x.chars()).collect();
    let Base64(block) = string_to_base64(&raw);

    let result = decrypt_aes_ecb(&block, "YELLOW SUBMARINE");
    let n = result.len();
    assert!(&result[n-23..] == "Play that funky music \n");
}

#[test]
fn challenge_8() {
    let mut f = File::open("data/8.txt").unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let tests: Vec<Vec<u8>> = s.split('\n').map(|l| {
        let Hex(v) = string_to_hex(&l);
        v
    }).collect();

    let result = test_for_aes_ecb(&tests);
    assert!(result[0] == 216);
    assert!(result[1] == 128);
    assert!(result[2] == 97);
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
        t.value == hex_to_string(string_to_hex(&t.value[..]))
    }
    quickcheck(equality_after_applying_twice as fn(Text) -> bool);
}
