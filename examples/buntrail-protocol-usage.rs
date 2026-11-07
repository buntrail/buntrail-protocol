fn main() {
    let mut decoder = buntrail_protocol::frame::Decoder::default();
    assert!(decoder.push(&[], None).unwrap().is_empty());
}
