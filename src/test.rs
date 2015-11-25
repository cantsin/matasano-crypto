
use quickcheck::{quickcheck, Gen, Arbitrary};

use util::{hex_to_raw, raw_to_base64, printable, HEX_ALPHABET};

#[test]
fn challenge_1() {
    // http://cryptopals.com/sets/1/challenges/1/
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let result = printable(&raw_to_base64(&hex_to_raw(input)), 64);
    assert!(result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
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
