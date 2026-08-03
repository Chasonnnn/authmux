use serde_json::Value;

#[test]
fn checked_in_status_schema_and_golden_are_valid_json() {
    let schema: Value = serde_json::from_str(include_str!("../docs/schemas/status-v1.schema.json"))
        .expect("checked-in status schema is valid JSON");
    let golden: Value = serde_json::from_str(include_str!("fixtures/golden/status-json.json"))
        .expect("checked-in status golden is valid JSON");

    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["properties"]["command"]["const"], "status");
    assert_eq!(golden["schema_version"], 1);
    assert_eq!(golden["command"], "status");
}

#[test]
fn checked_in_context_list_schema_and_golden_are_valid_json() {
    let schema: Value =
        serde_json::from_str(include_str!("../docs/schemas/context-list-v1.schema.json"))
            .expect("checked-in context-list schema is valid JSON");
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/golden/context-list-json.json"))
            .expect("checked-in context-list golden is valid JSON");

    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["properties"]["command"]["const"], "context_list");
    assert_eq!(golden["schema_version"], 1);
    assert_eq!(golden["command"], "context_list");
}
