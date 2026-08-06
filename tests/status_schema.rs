use serde_json::Value;

#[test]
fn checked_in_status_schema_and_golden_are_valid_json() {
    let schema: Value = serde_json::from_str(include_str!("../docs/schemas/status-v3.schema.json"))
        .expect("checked-in status schema is valid JSON");
    let golden: Value = serde_json::from_str(include_str!("fixtures/golden/status-json.json"))
        .expect("checked-in status golden is valid JSON");
    let ssh_golden: Value =
        serde_json::from_str(include_str!("fixtures/golden/status-ssh-json.json"))
            .expect("checked-in SSH status golden is valid JSON");

    assert_eq!(schema["properties"]["schema_version"]["const"], 3);
    assert_eq!(schema["properties"]["command"]["const"], "status");
    assert_eq!(golden["schema_version"], 3);
    assert_eq!(golden["command"], "status");
    assert_eq!(golden["observations"][0]["transport_reuse"], Value::Null);
    assert_eq!(ssh_golden["schema_version"], 3);
    assert_eq!(ssh_golden["observations"][0]["transport_reuse"], "active");
}

#[test]
fn checked_in_all_status_schema_is_valid_json() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../docs/schemas/status-all-v1.schema.json"))
            .expect("all-status schema is valid JSON");

    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["properties"]["command"]["const"], "status_all");
}

#[test]
fn checked_in_context_list_schema_and_golden_are_valid_json() {
    let schema: Value =
        serde_json::from_str(include_str!("../docs/schemas/context-list-v2.schema.json"))
            .expect("checked-in context-list schema is valid JSON");
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/golden/context-list-json.json"))
            .expect("checked-in context-list golden is valid JSON");

    assert_eq!(schema["properties"]["schema_version"]["const"], 2);
    assert_eq!(schema["properties"]["command"]["const"], "context_list");
    assert_eq!(golden["schema_version"], 2);
    assert_eq!(golden["command"], "context_list");
}

#[test]
fn checked_in_doctor_schema_and_golden_are_valid_json() {
    let schema: Value = serde_json::from_str(include_str!("../docs/schemas/doctor-v1.schema.json"))
        .expect("checked-in doctor schema is valid JSON");
    let golden: Value = serde_json::from_str(include_str!("fixtures/golden/doctor-json.json"))
        .expect("checked-in doctor golden is valid JSON");

    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["properties"]["command"]["const"], "doctor");
    assert_eq!(golden["schema_version"], 1);
    assert_eq!(golden["command"], "doctor");
}
