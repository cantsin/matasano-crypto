
use conversion::*;
use util::*;

#[test]
fn challenge_1() {
    let sample = "YELLOW SUBMARINE";
    let result = pad_pkcs7(&string_to_raw(sample), 20);
    assert!(raw_to_string(&result) == "YELLOW SUBMARINE\u{04}\u{04}\u{04}\u{04}")
}
