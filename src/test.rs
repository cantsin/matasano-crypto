
use quickcheck::{quickcheck, Gen, Arbitrary};

use util::*;

#[test]
fn challenge_1() {
    // http://cryptopals.com/sets/1/challenges/1/
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let result = printable(&raw_to_base64(&hex_to_raw(input)), 64);
    assert!(result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test]
fn challenge_2() {
    let x = hex_to_raw("1c0111001f010100061a024b53535009181c");
    let y = hex_to_raw("686974207468652062756c6c277320657965");
    let result = printable(&xor(&x, &y), 16);
    assert!(result == "746865206B696420646F6E277420706C6179");
}

#[test]
fn challenge_3() {
    let encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let v = hex_to_raw(encrypted);

    fn as_ascii(v: &Vec<u8>) -> String {
        v.iter().map(|&x| x as char).collect()
    }

    for i in b'A'..b'Z' + 1 {
        print!("{}\n", as_ascii(&xor_one(&v, i as u8)));
    }
    assert!(false);
}

#[derive(Clone, Debug)]
struct Text {
    value: String
}

impl Arbitrary for Text {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let len = u16::arbitrary(g);
        let mut s = String::with_capacity(len as usize);
        // don't pick a leading zero
        let i = usize::arbitrary(g);
        let i = i % HEX_ALPHABET[1..].len();
        s.push(HEX_ALPHABET[1..].as_bytes()[i] as char);

        for _ in 1..len {
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
        t.value == printable(&hex_to_raw(&t.value[..]), 16)
    }
    quickcheck(equality_after_applying_twice as fn(Text) -> bool);
}
