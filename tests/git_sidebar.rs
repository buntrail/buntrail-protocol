use buntrail_core::contracts as c;
use buntrail_protocol::{
    negotiation::Negotiated,
    services::*,
    types::{Header, Message},
};
#[test]
fn git_sidebar_wire_scopes_preserve_bytes_and_require_explicit_selection() {
    for scope in [
        c::GitHistoryScope::Head,
        c::GitHistoryScope::All,
        c::GitHistoryScope::References(vec![b"refs/heads/a-\xff".to_vec()]),
    ] {
        let wire = HistoryScope::from_core(&scope).unwrap();
        assert_eq!(
            serde_json::from_slice::<HistoryScope>(&serde_json::to_vec(&wire).unwrap())
                .unwrap()
                .core()
                .unwrap(),
            scope
        );
    }
    for json in [
        r#"{"kind":"references","refs":[]}"#,
        r#"{"kind":"references","refs":["!"]}"#,
        r#"{"kind":"head","refs":[]}"#,
    ] {
        assert!(serde_json::from_str::<HistoryScope>(json).map_or(true, |v| v.core().is_err()));
    }
}
#[test]
fn git_sidebar_capability_is_negotiated_only_when_advertised() {
    for advertised in [false, true] {
        let h = Header {
            major: 1,
            minor: 0,
            request_id: 1,
            context: None,
            operation_id: None,
            stream_id: None,
            sequence: None,
            message: Message::Hello {
                capabilities: if advertised {
                    vec!["git.sidebar.v1".into()]
                } else {
                    vec![]
                },
                max_header: 65536,
                max_payload: 1048576,
            },
        };
        assert_eq!(
            Negotiated::from_hello(&h)
                .unwrap()
                .supports("git.sidebar.v1"),
            advertised
        );
    }
}

#[test]
fn git_sidebar_golden_call_matches_schema_and_retains_exact_ref() {
    let call: Call = serde_json::from_slice(include_bytes!(
        "../protocol/v1/golden/git-sidebar-history.json"
    ))
    .unwrap();
    assert!(call.requires_sidebar());
    assert!(!call.mutating());
    let Call::SidebarHistory { scope, .. } = call else {
        panic!("expected scoped history")
    };
    assert_eq!(
        scope.core().unwrap(),
        c::GitHistoryScope::References(vec![b"refs/heads/a-\xff".to_vec()])
    );
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("../protocol/v1/services.schema.json")).unwrap();
    assert!(
        schema["$defs"]["Call"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["properties"]["method"]["const"] == "sidebar_history")
    );
}
