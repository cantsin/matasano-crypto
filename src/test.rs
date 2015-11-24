
use quickcheck::{quickcheck};

use util::{hex_to_raw, raw_to_base64, printable};

#[test]
fn challenge_1() {
    // http://cryptopals.com/sets/1/challenges/1/
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let result = printable(&raw_to_base64(&hex_to_raw(input)), 64);
    assert!(result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test]
fn hex_conversion_idempotent() {
    fn equality_after_applying_twice(s: String) -> bool {
        s == printable(&hex_to_raw(&s[..]), 16)
    }
    quickcheck(equality_after_applying_twice as fn(String) -> bool);
}
