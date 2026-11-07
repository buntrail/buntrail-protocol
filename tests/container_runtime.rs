use buntrail_core::contracts::*;
use buntrail_protocol::services::LeaseOwner;
use buntrail_protocol::types::{Header, Message};

#[test]
fn welcome_container_start_is_bounded_capability_guarded_and_ordinary_shape_is_unchanged() {
    let old = serde_json::json!({"major":1,"minor":0,"request_id":1,"context":null,"operation_id":null,"stream_id":null,"sequence":null,"kind":"welcome","metadata":{"capabilities":["services"],"max_header":65536,"max_payload":1048576,"initial_credit":524288,"target_binding":"target","runtime_generation":"11111111-1111-1111-1111-111111111111"}});
    let header: Header = serde_json::from_value(old.clone()).unwrap();
    header.validate(0, None).unwrap();
    assert_eq!(serde_json::to_value(header).unwrap(), old);
    let mut value = old;
    value["metadata"]["container_start_base64"] = serde_json::json!("c3RhcnQtMQ==");
    let header: Header = serde_json::from_value(value.clone()).unwrap();
    assert!(
        header.validate(0, None).is_err(),
        "container runtime requires explicit capability"
    );
    value["metadata"]["capabilities"] = serde_json::json!(["services", "container.binding.v1"]);
    let header: Header = serde_json::from_value(value.clone()).unwrap();
    header.validate(0, None).unwrap();
    assert!(matches!(
        header.message,
        Message::Welcome {
            container_start_base64: Some(_),
            ..
        }
    ));
    for invalid in ["!".to_string(), "a".repeat(345), String::new()] {
        value["metadata"]["container_start_base64"] = serde_json::json!(invalid);
        let header: Header = serde_json::from_value(value.clone()).unwrap();
        assert!(header.validate(0, None).is_err());
    }
}
#[test]
fn container_owner_roundtrips_start_and_rejects_oversized_or_malformed_generation() {
    let target = TargetIdentity {
        security_binding: b"host".to_vec(),
        effective_user: b"1000".to_vec(),
        filesystem_namespace: b"container".to_vec(),
        container: Some(ContainerIdentity {
            engine_endpoint: b"endpoint".to_vec(),
            immutable_id: vec![b'a'; 64],
        }),
    };
    let mut owner = WorkspaceLease {
        client: ClientID([1; 16]),
        workspace: WorkspaceID([2; 16]),
        lease: WorkspaceLeaseID([3; 16]),
        runtime: RuntimeGeneration {
            supervisor_boot: [4; 16],
            container_start: Some(b"start-1".to_vec()),
        },
    };
    let wire = LeaseOwner::from_core(&owner, &target).unwrap();
    assert_eq!(wire.container_start_base64.as_deref(), Some("c3RhcnQtMQ=="));
    let mut decoded: LeaseOwner =
        serde_json::from_slice(&serde_json::to_vec(&wire).unwrap()).unwrap();
    assert_eq!(
        decoded.container_start().unwrap(),
        Some(b"start-1".to_vec())
    );
    decoded.container_start_base64 = Some("!".into());
    assert!(decoded.validate().is_err());
    owner.runtime.container_start = Some(vec![0; 257]);
    assert!(LeaseOwner::from_core(&owner, &target).is_err());
    owner.runtime.container_start = None;
    let old = serde_json::to_value(LeaseOwner::from_core(&owner, &target).unwrap()).unwrap();
    assert!(
        old.get("container_start_base64").is_none(),
        "ordinary SSH owner frames retain their previous shape"
    );
}
