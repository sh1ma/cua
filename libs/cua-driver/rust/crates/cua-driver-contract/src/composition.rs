// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Canonical contracts for bounded desktop action composition.

use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

use crate::{
    Platform, SchemaMode, ToolAnnotations, ToolContract, ToolInput, ToolOutput,
    MULTI_CALL_SESSION_DESCRIPTION,
};

pub const ACT_AND_OBSERVE_DEFAULT_TIMEOUT_MS: i64 = 500;
pub const ACT_AND_OBSERVE_DEFAULT_POLL_INTERVAL_MS: i64 = 16;
pub const MAX_BATCH_ACTIONS: usize = 32;

const ALL_PLATFORMS: [Platform; 3] = [Platform::Macos, Platform::Windows, Platform::Linux];

fn positive_integer_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type": "integer", "minimum": 1})
}

fn non_empty_string_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type": "string", "minLength": 1})
}

fn arguments_object_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type": "object"})
}

mod json_object_string {
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::Value;

    pub fn serialize<S>(source: &String, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value: Value = serde_json::from_str(source).map_err(serde::ser::Error::custom)?;
        if !value.is_object() {
            return Err(serde::ser::Error::custom(
                "child arguments_json must encode a JSON object",
            ));
        }
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if !value.is_object() {
            return Err(D::Error::custom("child arguments must be a JSON object"));
        }
        serde_json::to_string(&value).map_err(D::Error::custom)
    }
}

/// One registry child call. Language bindings carry `arguments_json` as a
/// string, while serde exposes the canonical wire field as an object named
/// `arguments`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, uniffi::Record)]
#[serde(deny_unknown_fields)]
pub struct ChildInvocation {
    #[schemars(length(min = 1))]
    pub tool: String,
    #[serde(rename = "arguments", with = "json_object_string")]
    #[schemars(rename = "arguments", schema_with = "arguments_object_schema")]
    pub arguments_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, uniffi::Record)]
#[serde(deny_unknown_fields)]
pub struct ActAndObserveInput {
    pub action: ChildInvocation,
    #[schemars(schema_with = "positive_integer_schema")]
    pub pid: i64,
    #[schemars(schema_with = "positive_integer_schema")]
    pub window_id: u64,
    #[schemars(schema_with = "non_empty_string_schema")]
    pub screenshot_out_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(description = MULTI_CALL_SESSION_DESCRIPTION)]
    pub session: Option<String>,
    /// Default 500; the runtime clamps this to 1..5000 milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i64>,
    /// Default 16; the runtime clamps this to 1..250 milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<i64>,
}

impl ToolInput for ActAndObserveInput {
    const TOOL_NAME: &'static str = "act_and_observe";
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, uniffi::Record)]
#[serde(deny_unknown_fields)]
pub struct BatchActionsInput {
    #[schemars(length(min = 1, max = 32))]
    pub actions: Vec<ChildInvocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(description = MULTI_CALL_SESSION_DESCRIPTION)]
    pub session: Option<String>,
}

impl ToolInput for BatchActionsInput {
    const TOOL_NAME: &'static str = "batch_actions";
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, uniffi::Record)]
#[serde(deny_unknown_fields)]
pub struct CompositeChildOutput {
    pub tool: String,
    pub success: bool,
    pub elapsed_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, uniffi::Record)]
#[serde(deny_unknown_fields)]
pub struct ActAndObserveOutput {
    pub changed: bool,
    pub timed_out: bool,
    pub polls: u64,
    pub child: CompositeChildOutput,
    pub final_screenshot_path: String,
    pub action_elapsed_ms: u64,
    pub observe_elapsed_ms: u64,
    pub total_elapsed_ms: u64,
}

impl ToolOutput for ActAndObserveOutput {
    fn validate(&self) -> Result<(), String> {
        if self.changed == self.timed_out {
            return Err("exactly one of changed or timed_out must be true".to_owned());
        }
        if self.polls == 0 || !self.child.success || self.final_screenshot_path.is_empty() {
            return Err(
                "successful observation requires a poll, successful child, and path".into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, uniffi::Record)]
#[serde(deny_unknown_fields)]
pub struct BatchActionsOutput {
    pub requested: u64,
    pub completed: u64,
    #[schemars(required)]
    pub failed_index: Option<u64>,
    pub children: Vec<CompositeChildOutput>,
    pub elapsed_ms: u64,
    pub rollback: bool,
}

impl ToolOutput for BatchActionsOutput {
    fn validate(&self) -> Result<(), String> {
        if self.requested == 0
            || self.requested > MAX_BATCH_ACTIONS as u64
            || self.completed != self.requested
            || self.failed_index.is_some()
            || self.children.len() != self.requested as usize
            || self.children.iter().any(|child| !child.success)
            || self.rollback
        {
            return Err("successful batch summary is internally inconsistent".to_owned());
        }
        Ok(())
    }
}

pub fn contracts() -> Vec<ToolContract> {
    vec![
        ToolContract {
            name: ActAndObserveInput::TOOL_NAME.into(),
            description: "Execute one preflighted, authorized reversible desktop action exactly once, then poll screenshot-only captures of the same window until decoded RGBA pixels change or a bounded deadline expires. Pixel change is visual evidence only, not proof of semantic correctness. The final observed frame is written to screenshot_out_file.".into(),
            platforms: ALL_PLATFORMS.to_vec(),
            aliases: Vec::new(),
            capabilities: vec![
                "input.composite.act_and_observe".into(),
                "screen.capture".into(),
                "screen.capture.window".into(),
            ],
            annotations: ToolAnnotations {
                read_only: false,
                destructive: false,
                idempotent: false,
                open_world: false,
            },
            schema_mode: SchemaMode::CanonicalRuntime,
            cursor_semantics: None,
            input_schema: ActAndObserveInput::input_schema(),
            success_output_schema: Some(ActAndObserveOutput::output_schema()),
            output_validator: crate::validate_typed_output::<ActAndObserveOutput>,
        },
        ToolContract {
            name: BatchActionsInput::TOOL_NAME.into(),
            description: "Preflight 1 to 32 composable child actions, then execute them sequentially through the normal registry authorization path. Stop on the first runtime error and report the exact completed count and zero-based failed index. Already-completed actions are not rolled back.".into(),
            platforms: ALL_PLATFORMS.to_vec(),
            aliases: Vec::new(),
            capabilities: vec!["input.composite.batch".into()],
            annotations: ToolAnnotations {
                read_only: false,
                destructive: false,
                idempotent: false,
                open_world: false,
            },
            schema_mode: SchemaMode::CanonicalRuntime,
            cursor_semantics: None,
            input_schema: BatchActionsInput::input_schema(),
            success_output_schema: Some(BatchActionsOutput::output_schema()),
            output_validator: crate::validate_typed_output::<BatchActionsOutput>,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn child_arguments_are_objects_on_the_wire() {
        let child = ChildInvocation {
            tool: "click".into(),
            arguments_json: json!({"x": 1, "y": 2}).to_string(),
        };
        assert_eq!(
            serde_json::to_value(&child).unwrap(),
            json!({"tool": "click", "arguments": {"x": 1, "y": 2}})
        );
    }

    #[test]
    fn batch_schema_is_bounded() {
        let schema = BatchActionsInput::input_schema();
        assert_eq!(schema["properties"]["actions"]["minItems"], 1);
        assert_eq!(schema["properties"]["actions"]["maxItems"], 32);
        assert_eq!(
            schema["properties"]["actions"]["items"]["properties"]["arguments"]["type"],
            "object"
        );
    }
}
