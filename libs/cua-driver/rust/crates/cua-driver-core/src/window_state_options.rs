//! Shared output-selection semantics for `get_window_state`.
//!
//! Platform implementations own capture and accessibility details, but the
//! public opt-in/opt-out contract must be identical on every platform.

use serde_json::{json, Value};

use crate::protocol::ToolResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowStateSelection {
    pub include_tree: bool,
    pub include_screenshot: bool,
}

impl WindowStateSelection {
    /// Resolve the canonical `include_tree` flag, retaining
    /// `include_accessibility_tree` as a compatibility alias.
    ///
    /// The canonical spelling wins when both are supplied. A non-empty output
    /// path always forces capture. The empty-selection refusal is returned by
    /// this pure helper so callers can run it before any platform I/O.
    pub fn from_args(args: &Value) -> Result<Self, ToolResult> {
        let include_tree = args
            .get("include_tree")
            .and_then(Value::as_bool)
            .or_else(|| {
                args.get("include_accessibility_tree")
                    .and_then(Value::as_bool)
            })
            .unwrap_or(true);
        let file_output_requested = args
            .get("screenshot_out_file")
            .and_then(Value::as_str)
            .is_some_and(|path| !path.is_empty());
        let include_screenshot = args
            .get("include_screenshot")
            .and_then(Value::as_bool)
            .unwrap_or(true)
            || file_output_requested;

        if !include_tree && !include_screenshot {
            return Err(ToolResult::error(
                "Nothing to return: include_tree:false and include_screenshot:false were both requested without a non-empty screenshot_out_file.",
            )
            .with_structured(json!({
                "code": "no_output_requested",
                "tree_included": false,
                "screenshot_included": false,
            })));
        }

        Ok(Self {
            include_tree,
            include_screenshot,
        })
    }
}

pub fn include_tree_schema() -> Value {
    json!({
        "type": "boolean",
        "description": "Default true. Set false to skip the platform accessibility-tree walk, element-cache mutation, tokens, and tree-authoritative fields. The legacy include_accessibility_tree spelling remains accepted when include_tree is absent."
    })
}

pub fn legacy_include_accessibility_tree_schema() -> Value {
    json!({
        "type": "boolean",
        "deprecated": true,
        "description": "Deprecated compatibility alias for include_tree. When both are supplied, include_tree takes precedence."
    })
}

#[cfg(test)]
mod tests {
    use super::WindowStateSelection;
    use serde_json::json;

    #[test]
    fn defaults_to_tree_and_screenshot() {
        assert_eq!(
            WindowStateSelection::from_args(&json!({})).unwrap(),
            WindowStateSelection {
                include_tree: true,
                include_screenshot: true,
            }
        );
    }

    #[test]
    fn canonical_tree_flag_wins_over_legacy_alias() {
        assert!(
            !WindowStateSelection::from_args(&json!({
                "include_tree": false,
                "include_accessibility_tree": true,
            }))
            .unwrap()
            .include_tree
        );
    }

    #[test]
    fn non_empty_file_path_forces_capture() {
        let selection = WindowStateSelection::from_args(&json!({
            "include_tree": false,
            "include_screenshot": false,
            "screenshot_out_file": "/tmp/frame.png",
        }))
        .unwrap();
        assert!(selection.include_screenshot);
    }

    #[test]
    fn refusing_no_output_has_stable_code() {
        let result = WindowStateSelection::from_args(&json!({
            "include_tree": false,
            "include_screenshot": false,
        }))
        .unwrap_err();
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result
                .structured_content
                .as_ref()
                .and_then(|value| value.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("no_output_requested")
        );
    }
}
