use buntrail_core::contracts as c;
use buntrail_protocol::services::*;
#[test]
fn paths_and_evidence_round_trip_without_unicode_or_target_identity_loss() {
    let t = c::TargetIdentity {
        security_binding: b"verified".to_vec(),
        effective_user: b"user".to_vec(),
        filesystem_namespace: b"remote".to_vec(),
        container: None,
    };
    let p = c::TargetPath::posix(b"/repo/a-\xff\n".to_vec()).unwrap();
    assert_eq!(target_path(&path(&p).unwrap()).unwrap(), p);
    let file = c::FileRef {
        target: t.clone(),
        path: p,
        resolved_identity: Some(vec![0, 255]),
    };
    let dto = File::from_core(&file).unwrap();
    let bytes = serde_json::to_vec(&dto).unwrap();
    assert!(!bytes.contains(&255));
    assert_eq!(
        serde_json::from_slice::<File>(&bytes)
            .unwrap()
            .core(&t)
            .unwrap(),
        file
    );
    let operation = c::OperationReceipt {
        id: c::OperationID([8; 16]),
        state: c::OperationState::Unknown(c::ReconciliationEvidence {
            target: t.clone(),
            observed: c::ObservedState::File {
                file,
                version: None,
                digest: Some([9; 32]),
            },
            explanation: "inspect original".into(),
        }),
    };
    assert_eq!(
        Receipt::from_core(&operation).unwrap().core(&t).unwrap(),
        operation
    );
    assert!(digest(&"λ".repeat(32)).is_err());
}
#[test]
fn nullable_fields_are_required_and_nested_unknown_fields_rejected() {
    assert!(serde_json::from_str::<File>(r#"{"path_base64":"L3RtcA=="}"#).is_err());
    assert!(
        serde_json::from_str::<File>(
            r#"{"path_base64":"L3RtcA==","resolved_identity":null,"display_path":"/spoofed"}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<Call>(r#"{"method":"git_mutate","worktree":{"path_base64":"L3RtcA==","common_directory_base64":""},"expected":{"head":{"kind":"unborn","name_base64":"bWFpbg=="},"index_digest":"00","worktree_digest":"00"},"command":{"kind":"checkout","reference":"bWFpbg=="},"coordinator_approved":true}"#).is_err());
}
#[test]
fn terminal_receipt_preserves_runtime_and_output_bytes_round_trip() {
    let target = c::TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let receipt = c::OperationReceipt {
        id: c::OperationID([4; 16]),
        state: c::OperationState::Confirmed(c::MutationResult::TerminalOpened {
            session: c::TerminalSessionID([5; 16]),
            runtime: c::RuntimeGeneration {
                supervisor_boot: [6; 16],
                container_start: Some(vec![0, 255]),
            },
        }),
    };
    assert_eq!(
        Receipt::from_core(&receipt).unwrap().core(&target).unwrap(),
        receipt
    );
    let output = c::TerminalEvent::Output {
        sequence: 9,
        bytes: vec![0, 255, 27],
    };
    assert_eq!(
        buntrail_protocol::terminal::Event::from_core(output.clone())
            .core()
            .unwrap(),
        output
    );
    assert!(buntrail_protocol::terminal::size(0, 24).is_err());
}

#[test]
fn terminal_exit_code_nullable_field_is_required() {
    assert!(
        serde_json::from_str::<buntrail_protocol::terminal::Event>(r#"{"kind":"process_exit"}"#)
            .is_err()
    );
}

#[test]
fn owner_observation_golden_payloads_require_exact_typed_states() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol/v1/golden");
    for state in ["active", "detached", "absent", "runtime_lost"] {
        let bytes = std::fs::read(root.join(format!("valid-lease-observed-{state}.bin"))).unwrap();
        let header = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let reply: Reply = serde_json::from_slice(&bytes[8 + header..]).unwrap();
        assert!(matches!(reply, Reply::LeaseObserved { .. }));
    }
    let invalid: Vec<serde_json::Value> = serde_json::from_slice(
        &std::fs::read(root.join("lease-observation-invalid-payloads.json")).unwrap(),
    )
    .unwrap();
    for value in invalid {
        assert!(serde_json::from_value::<Reply>(value).is_err());
    }
}

#[test]
fn git_lookup_golden_is_read_only_and_requires_original_operation_and_nullable_receipt() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol/v1/golden");
    let bytes = std::fs::read(root.join("valid-git-existing.bin")).unwrap();
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let header: buntrail_protocol::types::Header =
        serde_json::from_slice(&bytes[8..8 + length]).unwrap();
    let buntrail_protocol::types::Message::ServiceCall { call } = &header.message else {
        panic!("lookup call");
    };
    assert!(matches!(call, Call::GitExisting { .. }));
    assert!(!call.mutating());
    assert!(!call.effectful());
    let mut missing = header.clone();
    missing.operation_id = None;
    assert!(missing.validate(0, header.context.as_ref()).is_err());
    let mut bypass = serde_json::to_value(call).unwrap();
    bypass["execution_expected"] = serde_json::json!({});
    assert!(serde_json::from_value::<Call>(bypass).is_err());
    assert!(serde_json::from_str::<Reply>(r#"{"kind":"git_existing"}"#).is_err());
    assert!(matches!(
        serde_json::from_str::<Reply>(r#"{"kind":"git_existing","receipt":null}"#).unwrap(),
        Reply::GitExisting { receipt: None }
    ));
}

#[test]
fn fixed_git_inspection_queries_cannot_encode_mutating_flags() {
    for query in [
        c::GitRead::StatusShort,
        c::GitRead::Refs,
        c::GitRead::Graph,
        c::GitRead::Stashes,
        c::GitRead::Upstream,
    ] {
        let json = serde_json::to_value(query).unwrap();
        assert_eq!(serde_json::from_value::<c::GitRead>(json).unwrap(), query);
    }
    assert!(
        serde_json::from_value::<c::GitRead>(serde_json::json!({"args":["clean","-fd"]})).is_err()
    );
    assert!(c::GitRead::from_args(&["checkout", "main"]).is_none());
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("../protocol/v1/services.schema.json")).unwrap();
    assert!(
        schema["$defs"]["Call"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["properties"]["method"]["const"] == "git_read")
    );
}
