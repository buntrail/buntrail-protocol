use buntrail_protocol::{frame::*, types::*};
fn hello() -> Vec<u8> {
    let h = br#"{"major":1,"minor":0,"request_id":1,"context":null,"operation_id":null,"stream_id":null,"sequence":null,"kind":"hello","metadata":{"capabilities":[],"max_header":65536,"max_payload":1048576}}"#;
    frame(h, &[])
}

#[test]
fn owned_save_commit_requires_explicit_lease_and_original_operation() {
    let value = serde_json::json!({"major":1,"minor":0,"request_id":1,
        "context":{"client_id":"11111111-1111-1111-1111-111111111111","workspace_id":"22222222-2222-2222-2222-222222222222","target_binding":"target","runtime_generation":"33333333-3333-3333-3333-333333333333"},
        "operation_id":"44444444-4444-4444-4444-444444444444","stream_id":null,"sequence":null,
        "kind":"file.save.commit_owned","metadata":{"transfer_id":"55555555-5555-5555-5555-555555555555","lease_id":"66666666-6666-6666-6666-666666666666","submitted_revision":2,"expected_version":null}});
    let header: Header = serde_json::from_value(value.clone()).expect("owned-save DTO must decode");
    header.validate(0, header.context.as_ref()).unwrap();
    for field in ["lease_id", "transfer_id"] {
        let mut invalid = value.clone();
        invalid["metadata"][field] = serde_json::json!("bad");
        let header: Header = serde_json::from_value(invalid).unwrap();
        assert!(header.validate(0, header.context.as_ref()).is_err());
    }
    let mut missing = value.clone();
    missing["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("lease_id");
    assert!(serde_json::from_value::<Header>(missing).is_err());
    let mut missing = value;
    missing["operation_id"] = serde_json::Value::Null;
    let header: Header = serde_json::from_value(missing).unwrap();
    assert!(header.validate(0, header.context.as_ref()).is_err());
}
fn frame(h: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend((h.len() as u32).to_be_bytes());
    v.extend((payload.len() as u32).to_be_bytes());
    v.extend(h);
    v.extend(payload);
    v
}
#[test]
fn partial_prefix_header_and_payload() {
    let bytes = hello();
    for cut in 1..bytes.len() {
        let mut d = Decoder::default();
        assert!(d.push(&bytes[..cut], None).unwrap().is_empty());
        assert!(d.finish().is_err());
        let frames = d.push(&bytes[cut..], None).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(d.finish().is_ok());
    }
}
#[test]
fn invalid_header_rejected_before_payload_allocation() {
    let mut d = Decoder::default();
    let mut bytes = frame(b"{bad", &[]);
    bytes[4..8].copy_from_slice(&1048576u32.to_be_bytes());
    assert!(d.push(&bytes, None).is_err());
    assert_eq!(d.buffered_payload_bytes(), 0);
    for (h, p) in [(65537u32, 0u32), (1, 1048577)] {
        let mut d = Decoder::default();
        let mut prefix = h.to_be_bytes().to_vec();
        prefix.extend(p.to_be_bytes());
        assert!(d.push(&prefix, None).is_err());
    }
    let mut unknown = hello();
    let position = unknown
        .windows(9)
        .position(|w| w == b"\"major\":1")
        .unwrap();
    unknown[position + 8] = b'2';
    assert!(Decoder::default().push(&unknown, None).is_err());
}
#[test]
fn mismatched_ids_and_invalid_paths() {
    let context = Context {
        workspace_id: "11111111-1111-1111-1111-111111111111".into(),
        client_id: "22222222-2222-2222-2222-222222222222".into(),
        target_binding: "host".into(),
        runtime_generation: "boot".into(),
    };
    let h = Header {
        major: 1,
        minor: 0,
        request_id: 1,
        context: Some(context.clone()),
        operation_id: None,
        stream_id: None,
        sequence: None,
        message: Message::FileList {
            path_base64: "Lw==".into(),
        },
    };
    let bytes = frame(&serde_json::to_vec(&h).unwrap(), &[]);
    assert!(Decoder::default().push(&bytes, None).is_err());
    assert_eq!(
        Decoder::default()
            .push(&bytes, Some(&context))
            .unwrap()
            .len(),
        1
    );
    assert!(decode_path("AA==").is_err());
    assert!(decode_path("%%%=").is_err());
}

#[test]
fn retired_replies_are_discarded_but_commands_and_malformed_frames_still_fail() {
    let context: Context =
        serde_json::from_slice(include_bytes!("../protocol/v1/golden/context.json")).unwrap();
    let mut header = Header {
        major: 1,
        minor: 0,
        request_id: 10,
        context: Some(context.clone()),
        operation_id: None,
        stream_id: None,
        sequence: None,
        message: Message::Ack {},
    };
    let encode = |header: &Header| frame(&serde_json::to_vec(header).unwrap(), &[]);
    assert!(
        Decoder::default()
            .push_replies(&encode(&header), |_| None)
            .unwrap()
            .is_empty()
    );
    let mut decoder = Decoder::default();
    let bytes = encode(&header);
    assert!(
        decoder
            .push_replies(&bytes[..bytes.len() - 1], |_| None)
            .unwrap()
            .is_empty()
    );
    assert!(
        decoder
            .push_replies(&bytes[bytes.len() - 1..], |_| None)
            .unwrap()
            .is_empty()
    );
    header.request_id = 11;
    assert_eq!(
        decoder
            .push_replies(&encode(&header), |id| (id == 11)
                .then(|| (context.clone(), None)))
            .unwrap()
            .len(),
        1
    );
    header.message = Message::Read {
        path_base64: "Lw==".into(),
    };
    assert!(
        Decoder::default()
            .push_replies(&encode(&header), |_| None)
            .is_err()
    );
    header.message = Message::Ack {};
    header.major = 2;
    assert!(
        Decoder::default()
            .push_replies(&encode(&header), |_| None)
            .is_err()
    );
    header.major = 1;
    header.context = None;
    assert!(
        Decoder::default()
            .push_replies(&encode(&header), |_| None)
            .is_err()
    );
    assert!(
        Decoder::default()
            .push_replies(&frame(b"{bad", &[]), |_| None)
            .is_err()
    );
    // General/helper decoding never gains the client-only discard path.
    header.context = Some(context);
    assert!(Decoder::default().push(&encode(&header), None).is_err());
}
#[test]
fn transfer_rejects_gaps_overlap_excess_and_bad_digest() {
    use sha2::{Digest, Sha256};
    let id = "33333333-3333-3333-3333-333333333333";
    let mut t = TransferVerifier::new(id.into(), 3).unwrap();
    assert!(t.chunk(id, 1, b"a").is_err());
    assert!(t.chunk(id, 0, b"abcd").is_err());
    assert!(t.chunk("wrong", 0, b"a").is_err());
    t.chunk(id, 0, b"a").unwrap();
    assert!(t.chunk(id, 0, b"a").is_err());
    assert!(t.end(id, [0; 32]).is_err());
    t.chunk(id, 1, b"bc").unwrap();
    assert!(t.end(id, [0; 32]).is_err());
    t.end(id, Sha256::digest(b"abc").into()).unwrap();
    assert!(t.chunk(id, 3, b"x").is_err());
}
#[test]
fn golden_frames() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol/v1/golden");
    let context: Context =
        serde_json::from_slice(&std::fs::read(root.join("context.json")).unwrap()).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    for fixture in manifest.as_array().unwrap() {
        let name = fixture["file"].as_str().unwrap();
        let bytes = std::fs::read(root.join(name)).unwrap();
        let mut d = Decoder::default();
        let result = d.push(&bytes, Some(&context));
        let valid = result.is_ok() && d.finish().is_ok();
        assert_eq!(valid, fixture["valid"].as_bool().unwrap(), "{name}");
    }
    let bytes = std::fs::read(root.join("valid-terminal.bin")).unwrap();
    for cut in 1..bytes.len() {
        let mut d = Decoder::default();
        assert!(d.push(&bytes[..cut], Some(&context)).unwrap().is_empty());
        assert!(d.finish().is_err());
        assert_eq!(d.push(&bytes[cut..], Some(&context)).unwrap().len(), 1);
    }
}
#[test]
fn schema_requires_explicit_nullable_fields() {
    let h=br#"{"major":1,"minor":0,"request_id":1,"kind":"hello","metadata":{"capabilities":[],"max_header":65536,"max_payload":1048576}}"#;
    assert!(Decoder::default().push(&frame(h, &[]), None).is_err());
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("../protocol/v1/schema.json")).unwrap();
    assert_eq!(schema["properties"]["major"]["const"], 1);
    assert_eq!(schema["additionalProperties"], false);
    let golden = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol/v1/golden/valid-hello.bin"),
    )
    .unwrap();
    let parsed = Decoder::default().push(&golden, None).unwrap().remove(0);
    let value = serde_json::to_value(parsed.header).unwrap();
    for required in schema["required"].as_array().unwrap() {
        assert!(value.get(required.as_str().unwrap()).is_some());
    }
}

#[test]
fn cancel_target_zero_is_rejected_by_runtime_and_shared_schema_fixture() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol/v1/golden");
    let context: Context =
        serde_json::from_slice(&std::fs::read(root.join("context.json")).unwrap()).unwrap();
    let bytes = std::fs::read(root.join("invalid-cancel-zero.bin")).unwrap();
    assert!(
        Decoder::default().push(&bytes, Some(&context)).is_err(),
        "zero cancellation target passed runtime validation"
    );
    let mut valid = bytes;
    let position = valid
        .windows(14)
        .position(|w| w == b"\"request_id\":0")
        .unwrap();
    valid[position + 13] = b'1';
    assert_eq!(
        Decoder::default()
            .push(&valid, Some(&context))
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn helper_control_metadata_requires_explicit_nullable_fields_and_unscoped_welcome() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol/v1/golden");
    let context: Context =
        serde_json::from_slice(&std::fs::read(root.join("context.json")).unwrap()).unwrap();
    let mut h: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("valid-receipt-unknown.bin")).unwrap()[8..],
    )
    .unwrap();
    h["metadata"].as_object_mut().unwrap().remove("failure");
    assert!(
        Decoder::default()
            .push(
                &frame(&serde_json::to_vec(&h).unwrap(), &[]),
                Some(&context)
            )
            .is_err()
    );
    let mut h: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("valid-welcome.bin")).unwrap()[8..])
            .unwrap();
    h["operation_id"] = serde_json::json!("33333333-3333-4333-8333-333333333333");
    assert!(
        Decoder::default()
            .push(&frame(&serde_json::to_vec(&h).unwrap(), &[]), None)
            .is_err()
    );
}

#[test]
fn helper_late_controls_only_retain_pinned_bridge_identity() {
    let owner = Context {
        client_id: "11111111-1111-4111-8111-111111111111".into(),
        workspace_id: "22222222-2222-4222-8222-222222222222".into(),
        target_binding: "verified".into(),
        runtime_generation: "33333333-3333-4333-8333-333333333333".into(),
    };
    let mut h = Header {
        major: 1,
        minor: 0,
        request_id: 7,
        context: Some(owner.clone()),
        operation_id: None,
        stream_id: Some("44444444-4444-4444-8444-444444444444".into()),
        sequence: None,
        message: Message::Credit { bytes: 1 },
    };
    let decode = |h: Header, payload: Vec<u8>, bridge: Option<&Context>| {
        Decoder::default().push_helper_requests(
            &Frame { header: h, payload }.encode().unwrap(),
            |_| false,
            bridge,
        )
    };
    assert_eq!(decode(h.clone(), vec![], Some(&owner)).unwrap().len(), 1);
    assert!(decode(h.clone(), vec![], None).is_err());
    for field in 0..3 {
        let mut bad = h.clone();
        let context = bad.context.as_mut().unwrap();
        match field {
            0 => context.client_id = "55555555-5555-4555-8555-555555555555".into(),
            1 => context.target_binding = "other".into(),
            _ => context.runtime_generation = "66666666-6666-4666-8666-666666666666".into(),
        };
        assert!(decode(bad, vec![], Some(&owner)).is_err());
    }
    assert!(decode(h.clone(), vec![1], Some(&owner)).is_err());
    h.major = 2;
    assert!(decode(h.clone(), vec![], Some(&owner)).is_err());
    h.major = 1;
    h.sequence = Some(1);
    assert!(decode(h.clone(), vec![], Some(&owner)).is_err());
    h.sequence = None;
    h.stream_id = None;
    h.message = Message::Cancel { request_id: 8 };
    assert_eq!(decode(h.clone(), vec![], Some(&owner)).unwrap().len(), 1);
    for message in [
        Message::Authentication {
            ssh_auth_sock: None,
        },
        Message::ServiceCall {
            call: buntrail_protocol::services::Call::TerminalInput {
                lease_id: owner.workspace_id.clone(),
                session_id: owner.workspace_id.clone(),
            },
        },
        Message::Ack {},
    ] {
        h.message = message;
        assert!(decode(h.clone(), vec![], Some(&owner)).is_err());
    }
}
