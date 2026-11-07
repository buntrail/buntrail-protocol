use buntrail_core::contracts::TargetPath;
use buntrail_protocol::types::WirePath;

#[test]
fn wire_paths_preserve_windows_units_and_posix_bytes() {
    let windows = TargetPath::WindowsWide(vec![67, 58, 92, 0xd800]);
    let wire = WirePath::from_core(&windows).unwrap();
    assert_eq!(
        serde_json::to_value(&wire).unwrap(),
        serde_json::json!({"kind":"windows","base64":"QwA6AFwAANg="})
    );
    assert_eq!(wire.core(), windows);
    let decoded: WirePath =
        serde_json::from_value(serde_json::json!({"kind":"windows","base64":"QwA6AFwAANg="}))
            .unwrap();
    assert_eq!(decoded.core(), windows);
    let posix = TargetPath::PosixBytes(vec![47, 255]);
    let wire = WirePath::from_core(&posix).unwrap();
    assert_eq!(
        serde_json::to_value(&wire).unwrap(),
        serde_json::json!({"kind":"posix","base64":"L/8="})
    );
    assert_eq!(wire.core(), posix);
    let decoded: WirePath =
        serde_json::from_value(serde_json::json!({"kind":"posix","base64":"L/8="})).unwrap();
    assert_eq!(decoded.core(), posix);
    let decoded: WirePath =
        serde_json::from_value(serde_json::json!({"kind":"windows","base64":"QwA6AFwAPdiH3A=="}))
            .unwrap();
    assert_eq!(
        decoded.core(),
        TargetPath::WindowsWide(vec![67, 58, 92, 0xd83d, 0xdc87])
    );
}

#[test]
fn wire_paths_validate_before_use() {
    for value in [
        serde_json::json!({"kind":"windows","base64":"QwA6AFw="}),
        serde_json::json!({"kind":"windows","base64":"QwA6AHgA"}),
        serde_json::json!({"kind":"windows","base64":"QwA6AFwAAAA="}),
        serde_json::json!({"kind":"posix","base64":"AA=="}),
        serde_json::json!({"kind":"posix","base64":"%%%="}),
    ] {
        assert!(serde_json::from_value::<WirePath>(value).is_err());
    }
    for value in [
        serde_json::json!("Lw=="),
        serde_json::json!({"kind":"other","base64":"Lw=="}),
        serde_json::json!({"kind":"posix","base64":"Lw==","display":"/spoof"}),
    ] {
        assert!(serde_json::from_value::<WirePath>(value).is_err());
    }
    assert!(WirePath::from_core(&TargetPath::WindowsWide(vec![67, 58, 120])).is_err());
    assert!(WirePath::from_core(&TargetPath::PosixBytes(vec![0])).is_err());
}

#[test]
fn wire_paths_reject_windows_device_aliases() {
    for encoded in [
        "QwA6AFwATgBVAEwA",
        "XABcAHMAZQByAHYAZQByAFwAcABpAHAAZQBcAG4AYQBtAGUA",
        "XABcAD8AXABVAE4AQwBcAHMAZQByAHYAZQByAFwASQBQAEMAJABcAG4AYQBtAGUA",
    ] {
        assert!(
            serde_json::from_value::<WirePath>(
                serde_json::json!({"kind":"windows","base64":encoded})
            )
            .is_err()
        );
    }
}
