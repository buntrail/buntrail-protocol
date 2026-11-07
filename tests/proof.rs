use buntrail_protocol::types::*;
fn header(kind: &str, metadata: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"major":1,"minor":0,"request_id":7,
        "context":{"client_id":"11111111-1111-1111-1111-111111111111","workspace_id":"22222222-2222-2222-2222-222222222222","target_binding":"target","runtime_generation":"33333333-3333-3333-3333-333333333333"},
        "operation_id":"44444444-4444-4444-4444-444444444444","stream_id":"55555555-5555-5555-5555-555555555555","sequence":null,"kind":kind,"metadata":metadata})
}
#[test]
fn proof_original_control_requires_exact_ids_and_chunk_sequence() {
    let value = header(
        "proof.lookup.begin",
        serde_json::json!({"transfer_id":"55555555-5555-5555-5555-555555555555","total_length":90000,"action":"prepare","lease_id":"66666666-6666-6666-6666-666666666666"}),
    );
    let h: Header =
        serde_json::from_value(value.clone()).expect("framed original prelookup must decode");
    h.validate(0, h.context.as_ref()).unwrap();
    for field in ["operation_id", "stream_id"] {
        let mut v = value.clone();
        v[field] = serde_json::Value::Null;
        let h: Header = serde_json::from_value(v).unwrap();
        assert!(h.validate(0, h.context.as_ref()).is_err());
    }
    for kind in [
        "proof.lookup.chunk",
        "proof.original.chunk",
        "proof.approvals.chunk",
        "proof.aliases.chunk",
        "proof.output.chunk",
    ] {
        let mut v = header(
            kind,
            serde_json::json!({"transfer_id":"55555555-5555-5555-5555-555555555555","offset":0}),
        );
        v["sequence"] = serde_json::json!(0);
        let h: Header = serde_json::from_value(v.clone()).unwrap();
        h.validate(1, h.context.as_ref()).unwrap();
        assert!(h.validate(0, h.context.as_ref()).is_err());
        assert!(h.validate(65537, h.context.as_ref()).is_err());
        v["sequence"] = serde_json::Value::Null;
        let h: Header = serde_json::from_value(v).unwrap();
        assert!(h.validate(1, h.context.as_ref()).is_err());
    }
    let mut h:Header=serde_json::from_value(header("proof.lookup.end",serde_json::json!({"transfer_id":"55555555-5555-5555-5555-555555555555","sha256":"ab".repeat(32)}))).unwrap();
    h.sequence = Some(2);
    h.validate(0, h.context.as_ref()).unwrap();
    assert!(h.validate(1, h.context.as_ref()).is_err());
    h.stream_id = Some("77777777-7777-7777-7777-777777777777".into());
    assert!(h.validate(0, h.context.as_ref()).is_err());
}

#[test]
fn existing_only_reply_is_explicit_and_requires_original_identity() {
    let value = header("proof.missing", serde_json::json!({}));
    let h: Header = serde_json::from_value(value.clone()).unwrap();
    assert!(matches!(h.message, Message::ProofMissing {}));
    h.validate(0, h.context.as_ref()).unwrap();
    let mut missing = value.clone();
    missing["operation_id"] = serde_json::Value::Null;
    let h: Header = serde_json::from_value(missing).unwrap();
    assert!(h.validate(0, h.context.as_ref()).is_err());
    let mut no_stream = value.clone();
    no_stream["stream_id"] = serde_json::Value::Null;
    let h: Header = serde_json::from_value(no_stream).unwrap();
    assert!(h.validate(0, h.context.as_ref()).is_err());
    let good: Header = serde_json::from_value(value.clone()).unwrap();
    let encoded = buntrail_protocol::frame::Frame {
        header: good.clone(),
        payload: vec![],
    }
    .encode()
    .unwrap();
    assert!(
        buntrail_protocol::frame::Decoder::default()
            .push_replies(&encoded, |_| Some((
                good.context.clone().unwrap(),
                Some("99999999-9999-9999-9999-999999999999".into())
            )))
            .is_err()
    );
    assert!(
        buntrail_protocol::frame::Decoder::default()
            .push_replies(&encoded, |_| None)
            .unwrap()
            .is_empty()
    );
    let mut extra = value;
    extra["metadata"]["receipt"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Header>(extra).is_err());
}
