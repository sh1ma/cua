//! Bounded, platform-independent desktop action composition.
//!
//! Child actions always re-enter [`ToolRegistry::invoke`], preserving the
//! existing authorization, policy, recording, and action-result path. Window
//! observations call the platform `get_window_state` implementation directly
//! only for the composite's already-authorized private screenshot baseline and
//! polling frames.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    protocol::{Content, ToolResult},
    recording_tools::ReplayRegistrySlot,
    tool::{Tool, ToolDef, ToolRegistry},
};

const DEFAULT_OBSERVE_TIMEOUT_MS: u64 =
    cua_driver_contract::ACT_AND_OBSERVE_DEFAULT_TIMEOUT_MS as u64;
const MIN_OBSERVE_TIMEOUT_MS: u64 = 1;
const MAX_OBSERVE_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_POLL_INTERVAL_MS: u64 =
    cua_driver_contract::ACT_AND_OBSERVE_DEFAULT_POLL_INTERVAL_MS as u64;
const MIN_POLL_INTERVAL_MS: u64 = 1;
const MAX_POLL_INTERVAL_MS: u64 = 250;
const EXCLUDED_COMPOSITE_CHILDREN: &[&str] = &[
    "act_and_observe",
    "batch_actions",
    "launch_app",
    "kill_app",
    "start_session",
    "end_session",
    "escalate_session",
    "start_recording",
    "stop_recording",
    "replay_trajectory",
    "install_ffmpeg",
    "mouse_button_down",
    "mouse_button_up",
    "page",
];

const REVERSIBLE_ELEVATED_INPUT_ALLOWLIST: &[&str] = &[
    "click",
    "double_click",
    "right_click",
    "drag",
    "scroll",
    "move_cursor",
    "mouse_drag",
    "parallel_mouse_drag",
    "type_text",
    "press_key",
    "hotkey",
    "set_value",
    "bring_to_front",
    "set_window_frame",
    "invoke_menu",
];

#[derive(Debug, Clone)]
struct PreparedAction {
    tool: String,
    arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PixelFingerprint {
    width: u32,
    height: u32,
    rgba_sha256: [u8; 32],
}

fn decoded_pixel_fingerprint(png: &[u8]) -> Result<PixelFingerprint, String> {
    let rgba = image::load_from_memory_with_format(png, image::ImageFormat::Png)
        .map_err(|error| format!("could not decode captured PNG: {error}"))?
        .to_rgba8();
    let (width, height) = rgba.dimensions();
    let rgba_sha256: [u8; 32] = Sha256::digest(rgba.as_raw()).into();
    Ok(PixelFingerprint {
        width,
        height,
        rgba_sha256,
    })
}

#[async_trait]
trait ScreenshotProvider: Send + Sync {
    async fn capture_png(
        &self,
        pid: i64,
        window_id: u64,
        output_path: &Path,
    ) -> Result<Vec<u8>, String>;
}

struct ToolScreenshotProvider {
    get_window_state: Arc<dyn Tool>,
}

impl ToolScreenshotProvider {
    fn new(get_window_state: Arc<dyn Tool>) -> Self {
        Self { get_window_state }
    }
}

#[async_trait]
impl ScreenshotProvider for ToolScreenshotProvider {
    async fn capture_png(
        &self,
        pid: i64,
        window_id: u64,
        output_path: &Path,
    ) -> Result<Vec<u8>, String> {
        let result = self
            .get_window_state
            .invoke(json!({
                "pid": pid,
                "window_id": window_id,
                "include_tree": false,
                "include_screenshot": false,
                "screenshot_out_file": output_path.to_string_lossy(),
                // Direct in-process observation must not mutate the action
                // element/token cache used by callers.
                "_observation_only": true,
            }))
            .await;
        if result.is_error == Some(true) {
            return Err(result_text(&result, "get_window_state capture failed"));
        }
        tokio::fs::read(output_path)
            .await
            .map_err(|error| format!("could not read captured screenshot: {error}"))
    }
}

struct PrivateCaptureDir {
    path: PathBuf,
}

impl PrivateCaptureDir {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "cua-driver-act-and-observe-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&path)
            .map_err(|error| format!("could not create private capture directory: {error}"))?;
        let directory = Self { path };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory.path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("could not protect private capture directory: {error}"))?;
        }
        Ok(directory)
    }

    fn frame_path(&self) -> PathBuf {
        self.path.join("frame.png")
    }
}

impl Drop for PrivateCaptureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn result_text(result: &ToolResult, fallback: &str) -> String {
    result
        .content
        .iter()
        .find_map(|content| match content {
            Content::Text { text, .. } => Some(text.clone()),
            Content::Image { .. } => None,
        })
        .unwrap_or_else(|| fallback.to_owned())
}

fn elapsed_ms(started: tokio::time::Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn clamped_millis(value: Option<&Value>, default: u64, minimum: u64, maximum: u64) -> u64 {
    match value {
        Some(value) if value.as_i64().is_some_and(|number| number < 0) => minimum,
        Some(value) => value.as_u64().unwrap_or(default).clamp(minimum, maximum),
        None => default,
    }
}

type ValidatorCache = HashMap<(String, [u8; 32]), Arc<jsonschema::Validator>>;

fn cached_validator(tool: &str, schema: &Value) -> Result<Arc<jsonschema::Validator>, ToolResult> {
    static VALIDATORS: OnceLock<Mutex<ValidatorCache>> = OnceLock::new();
    let schema_bytes = serde_json::to_vec(schema).map_err(|error| {
        ToolResult::error(format!("could not serialize {tool} input schema: {error}"))
            .with_structured(json!({"code": "invalid_tool_schema", "tool": tool}))
    })?;
    let schema_hash: [u8; 32] = Sha256::digest(&schema_bytes).into();
    let key = (tool.to_owned(), schema_hash);
    let cache = VALIDATORS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(validator) = cache.lock().unwrap().get(&key).cloned() {
        return Ok(validator);
    }
    let validator = Arc::new(jsonschema::validator_for(schema).map_err(|error| {
        ToolResult::error(format!("{tool} publishes an invalid input schema: {error}"))
            .with_structured(json!({
                "code": "invalid_tool_schema",
                "tool": tool,
            }))
    })?);
    let mut cache = cache.lock().unwrap();
    cache.retain(|(cached_tool, _), _| cached_tool != tool);
    cache.insert(key, validator.clone());
    Ok(validator)
}

fn validate_schema(tool: &str, schema: &Value, arguments: &Value) -> Result<(), ToolResult> {
    let validator = cached_validator(tool, schema)?;
    if !validator.is_valid(arguments) {
        return Err(ToolResult::error(format!(
            "arguments for {tool} do not match its input schema"
        ))
        .with_structured(json!({
            "code": "child_schema_validation_failed",
            "tool": tool,
        })));
    }
    Ok(())
}

fn is_explicitly_excluded(tool: &str) -> bool {
    EXCLUDED_COMPOSITE_CHILDREN.contains(&tool) || tool.starts_with("browser_")
}

fn is_composable(definition: &ToolDef) -> bool {
    if definition.read_only || is_explicitly_excluded(&definition.name) {
        return false;
    }
    if !definition.destructive && !definition.open_world {
        return true;
    }
    REVERSIBLE_ELEVATED_INPUT_ALLOWLIST.contains(&definition.name.as_str())
}

fn schema_accepts(definition: &ToolDef, field: &str) -> bool {
    definition
        .runtime_input_schema()
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| properties.contains_key(field))
}

fn bind_i64_argument(
    arguments: &mut Map<String, Value>,
    field: &str,
    expected: i64,
) -> Result<(), ToolResult> {
    match arguments.get(field) {
        Some(value) if value.as_i64() == Some(expected) => Ok(()),
        Some(_) => Err(ToolResult::error(format!(
            "child {field} must match act_and_observe {field}"
        ))
        .with_structured(json!({
            "code": "child_target_mismatch",
            "field": field,
        }))),
        None => {
            arguments.insert(field.to_owned(), json!(expected));
            Ok(())
        }
    }
}

fn bind_u64_argument(
    arguments: &mut Map<String, Value>,
    field: &str,
    expected: u64,
) -> Result<(), ToolResult> {
    match arguments.get(field) {
        Some(value) if value.as_u64() == Some(expected) => Ok(()),
        Some(_) => Err(ToolResult::error(format!(
            "child {field} must match act_and_observe {field}"
        ))
        .with_structured(json!({
            "code": "child_target_mismatch",
            "field": field,
        }))),
        None => {
            arguments.insert(field.to_owned(), json!(expected));
            Ok(())
        }
    }
}

fn bind_window_target(
    arguments: &mut Map<String, Value>,
    pid: i64,
    window_id: u64,
) -> Result<(), ToolResult> {
    match arguments.get("target") {
        Some(target)
            if target.get("kind").and_then(Value::as_str) == Some("window")
                && target.get("pid").and_then(Value::as_i64) == Some(pid)
                && target.get("window_id").and_then(Value::as_u64) == Some(window_id) =>
        {
            Ok(())
        }
        Some(_) => Err(ToolResult::error(
            "child target must match the act_and_observe window target",
        )
        .with_structured(json!({
            "code": "child_target_mismatch",
            "field": "target",
        }))),
        None => {
            arguments.insert(
                "target".to_owned(),
                json!({"kind": "window", "pid": pid, "window_id": window_id}),
            );
            Ok(())
        }
    }
}

fn prepare_child(
    registry: &ToolRegistry,
    raw: &Value,
    target: Option<(i64, u64)>,
    parent_session: Option<&Value>,
) -> Result<PreparedAction, ToolResult> {
    let tool = raw
        .get("tool")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ToolResult::error("child action requires a string tool field")
                .with_structured(json!({"code": "invalid_child_action"}))
        })?
        .to_owned();
    let definition = registry.get_def(&tool).cloned().ok_or_else(|| {
        ToolResult::error(format!("unknown child tool: {tool}")).with_structured(json!({
            "code": "unknown_child_tool",
            "tool": tool,
        }))
    })?;
    if !is_composable(&definition) {
        return Err(
            ToolResult::error(format!("child tool {tool} is not composable")).with_structured(
                json!({
                    "code": "child_not_composable",
                    "tool": tool,
                }),
            ),
        );
    }

    let mut arguments = raw.get("arguments").cloned().ok_or_else(|| {
        ToolResult::error("child action requires an arguments object")
            .with_structured(json!({"code": "invalid_child_action"}))
    })?;
    let Some(argument_object) = arguments.as_object_mut() else {
        return Err(
            ToolResult::error("child action arguments must be an object")
                .with_structured(json!({"code": "invalid_child_action"})),
        );
    };

    if let Some((pid, window_id)) = target {
        let accepts_flat_target =
            schema_accepts(&definition, "pid") && schema_accepts(&definition, "window_id");
        let accepts_typed_target = schema_accepts(&definition, "target");
        if argument_object.contains_key("target") && accepts_typed_target {
            bind_window_target(argument_object, pid, window_id)?;
        } else if accepts_flat_target {
            bind_i64_argument(argument_object, "pid", pid)?;
            bind_u64_argument(argument_object, "window_id", window_id)?;
        } else if accepts_typed_target {
            bind_window_target(argument_object, pid, window_id)?;
        } else {
            return Err(ToolResult::error(format!(
                "child tool {tool} cannot prove the act_and_observe window target"
            ))
            .with_structured(json!({
                "code": "child_target_unsupported",
                "tool": tool,
            })));
        }
    }
    if schema_accepts(&definition, "session") && !argument_object.contains_key("session") {
        if let Some(session) = parent_session {
            argument_object.insert("session".to_owned(), session.clone());
        }
    }

    validate_schema(&tool, &definition.runtime_input_schema(), &arguments)?;
    Ok(PreparedAction { tool, arguments })
}

fn child_summary(tool: &str, result: &ToolResult, elapsed_ms: u64) -> Value {
    let mut summary = json!({
        "tool": tool,
        "success": result.is_error != Some(true),
        "elapsed_ms": elapsed_ms,
    });
    if let Some(effect) = result
        .structured_content
        .as_ref()
        .and_then(|value| value.get("effect"))
        .and_then(Value::as_str)
    {
        summary["effect"] = json!(effect);
    }
    if let Some(code) = result
        .structured_content
        .as_ref()
        .and_then(|value| value.get("code").or_else(|| value.pointer("/refusal/code")))
        .and_then(Value::as_str)
    {
        summary["error_code"] = json!(code);
    }
    summary
}

pub struct ActAndObserveTool {
    registry: ReplayRegistrySlot,
    screenshots: Arc<dyn ScreenshotProvider>,
}

impl ActAndObserveTool {
    pub fn new(registry: ReplayRegistrySlot, get_window_state: Arc<dyn Tool>) -> Self {
        Self {
            registry,
            screenshots: Arc::new(ToolScreenshotProvider::new(get_window_state)),
        }
    }
}

static ACT_AND_OBSERVE_DEF: OnceLock<ToolDef> = OnceLock::new();

#[async_trait]
impl Tool for ActAndObserveTool {
    fn def(&self) -> &ToolDef {
        ACT_AND_OBSERVE_DEF.get_or_init(|| {
            let contract = cua_driver_contract::tool_contract("act_and_observe")
                .expect("act_and_observe contract must be published");
            ToolDef::from_contract(&contract)
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let total_started = tokio::time::Instant::now();
        let mut public_args = args.clone();
        crate::tool_args::sanitize_reserved_args(&mut public_args);
        if let Err(error) = validate_schema(
            "act_and_observe",
            &self.def().runtime_input_schema(),
            &public_args,
        ) {
            return error;
        }

        let pid = public_args["pid"].as_i64().expect("schema checked pid");
        let window_id = public_args["window_id"]
            .as_u64()
            .expect("schema checked window_id");
        let output_path = PathBuf::from(
            public_args["screenshot_out_file"]
                .as_str()
                .expect("schema checked screenshot_out_file"),
        );
        let timeout_ms = clamped_millis(
            public_args.get("timeout_ms"),
            DEFAULT_OBSERVE_TIMEOUT_MS,
            MIN_OBSERVE_TIMEOUT_MS,
            MAX_OBSERVE_TIMEOUT_MS,
        );
        let poll_interval_ms = clamped_millis(
            public_args.get("poll_interval_ms"),
            DEFAULT_POLL_INTERVAL_MS,
            MIN_POLL_INTERVAL_MS,
            MAX_POLL_INTERVAL_MS,
        );

        let Some(registry) = self.registry.lock().unwrap().upgrade() else {
            return ToolResult::error("act_and_observe registry is not initialized")
                .with_structured(json!({"code": "registry_unavailable"}));
        };
        let parent_session = args
            .get("session")
            .or_else(|| args.get("_public_session_label"));
        let action = match prepare_child(
            &registry,
            &public_args["action"],
            Some((pid, window_id)),
            parent_session,
        ) {
            Ok(action) => action,
            Err(error) => return error,
        };

        let private_dir = match PrivateCaptureDir::create() {
            Ok(directory) => directory,
            Err(error) => {
                return ToolResult::error(&error).with_structured(json!({
                    "code": "private_capture_setup_failed",
                }))
            }
        };
        let private_frame = private_dir.frame_path();
        let baseline_png = match self
            .screenshots
            .capture_png(pid, window_id, &private_frame)
            .await
        {
            Ok(png) => png,
            Err(error) => {
                return ToolResult::error(format!("baseline capture failed: {error}"))
                    .with_structured(json!({"code": "baseline_capture_failed"}))
            }
        };
        let baseline = match decoded_pixel_fingerprint(&baseline_png) {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                return ToolResult::error(&error)
                    .with_structured(json!({"code": "baseline_decode_failed"}))
            }
        };

        let action_started = tokio::time::Instant::now();
        let child_result = registry.invoke(&action.tool, action.arguments).await;
        let action_elapsed_ms = elapsed_ms(action_started);
        let child = child_summary(&action.tool, &child_result, action_elapsed_ms);
        if child_result.is_error == Some(true) {
            return ToolResult::error(format!("child action {} failed", action.tool))
                .with_structured(json!({
                    "code": "child_action_failed",
                    "changed": false,
                    "timed_out": false,
                    "polls": 0,
                    "child": child,
                    "action_elapsed_ms": action_elapsed_ms,
                    "observe_elapsed_ms": 0,
                    "total_elapsed_ms": elapsed_ms(total_started),
                }));
        }

        let observe_started = tokio::time::Instant::now();
        let deadline = observe_started + Duration::from_millis(timeout_ms);
        let mut polls = 0u64;
        let (changed, timed_out, final_png) = loop {
            polls += 1;
            let png = match self
                .screenshots
                .capture_png(pid, window_id, &private_frame)
                .await
            {
                Ok(png) => png,
                Err(error) => {
                    return ToolResult::error(format!("observation capture failed: {error}"))
                        .with_structured(json!({
                            "code": "observation_capture_failed",
                            "polls": polls,
                            "child": child,
                            "action_elapsed_ms": action_elapsed_ms,
                            "observe_elapsed_ms": elapsed_ms(observe_started),
                            "total_elapsed_ms": elapsed_ms(total_started),
                        }))
                }
            };
            let fingerprint = match decoded_pixel_fingerprint(&png) {
                Ok(fingerprint) => fingerprint,
                Err(error) => {
                    return ToolResult::error(&error).with_structured(json!({
                        "code": "observation_decode_failed",
                        "polls": polls,
                        "child": child,
                    }))
                }
            };
            if fingerprint != baseline {
                break (true, false, png);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break (false, true, png);
            }
            tokio::time::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(poll_interval_ms)),
            )
            .await;
        };
        if let Err(error) = tokio::fs::write(&output_path, &final_png).await {
            return ToolResult::error(format!("could not persist final screenshot: {error}"))
                .with_structured(json!({
                    "code": "final_screenshot_write_failed",
                    "polls": polls,
                    "child": child,
                }));
        }

        let observe_elapsed_ms = elapsed_ms(observe_started);
        ToolResult::text(if changed {
            format!("{} changed the target window after {polls} poll(s)", action.tool)
        } else {
            format!(
                "{} completed, but target-window pixels did not change before the observation deadline",
                action.tool
            )
        })
        .with_structured(json!({
            "changed": changed,
            "timed_out": timed_out,
            "polls": polls,
            "child": child,
            "final_screenshot_path": output_path.to_string_lossy(),
            "action_elapsed_ms": action_elapsed_ms,
            "observe_elapsed_ms": observe_elapsed_ms,
            "total_elapsed_ms": elapsed_ms(total_started),
        }))
    }
}

pub struct BatchActionsTool {
    registry: ReplayRegistrySlot,
}

impl BatchActionsTool {
    pub fn new(registry: ReplayRegistrySlot) -> Self {
        Self { registry }
    }
}

static BATCH_ACTIONS_DEF: OnceLock<ToolDef> = OnceLock::new();

#[async_trait]
impl Tool for BatchActionsTool {
    fn def(&self) -> &ToolDef {
        BATCH_ACTIONS_DEF.get_or_init(|| {
            let contract = cua_driver_contract::tool_contract("batch_actions")
                .expect("batch_actions contract must be published");
            ToolDef::from_contract(&contract)
        })
    }

    async fn invoke(&self, args: Value) -> ToolResult {
        let total_started = tokio::time::Instant::now();
        let mut public_args = args.clone();
        crate::tool_args::sanitize_reserved_args(&mut public_args);
        if let Err(error) = validate_schema(
            "batch_actions",
            &self.def().runtime_input_schema(),
            &public_args,
        ) {
            return error;
        }
        let Some(registry) = self.registry.lock().unwrap().upgrade() else {
            return ToolResult::error("batch_actions registry is not initialized")
                .with_structured(json!({"code": "registry_unavailable"}));
        };
        let parent_session = args
            .get("session")
            .or_else(|| args.get("_public_session_label"));
        let raw_actions = public_args["actions"]
            .as_array()
            .expect("schema checked actions");

        // Complete preflight before the first child can cause side effects.
        let mut actions = Vec::with_capacity(raw_actions.len());
        for raw in raw_actions {
            match prepare_child(&registry, raw, None, parent_session) {
                Ok(action) => actions.push(action),
                Err(error) => return error,
            }
        }

        let requested = actions.len();
        let mut completed = 0usize;
        let mut children = Vec::with_capacity(requested);
        for (index, action) in actions.into_iter().enumerate() {
            let child_started = tokio::time::Instant::now();
            let result = registry.invoke(&action.tool, action.arguments).await;
            let successful = result.is_error != Some(true);
            let mut summary = child_summary(&action.tool, &result, elapsed_ms(child_started));
            summary["index"] = json!(index);
            children.push(summary);
            if !successful {
                return ToolResult::error(format!(
                    "batch_actions stopped at child {index} ({})",
                    action.tool
                ))
                .with_structured(json!({
                    "requested": requested,
                    "completed": completed,
                    "failed_index": index,
                    "children": children,
                    "elapsed_ms": elapsed_ms(total_started),
                    "rollback": false,
                }));
            }
            completed += 1;
        }

        ToolResult::text(format!(
            "batch_actions completed {completed}/{requested} child actions"
        ))
        .with_structured(json!({
            "requested": requested,
            "completed": completed,
            "failed_index": Value::Null,
            "children": children,
            "elapsed_ms": elapsed_ms(total_started),
            "rollback": false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::decoded_pixel_fingerprint;
    use crate::{
        authorization::PermissionMode,
        protocol::ToolResult,
        session_authorization::{SessionAuthorizationRegistry, SessionModeCeiling},
        tool::{Tool, ToolDef, ToolRegistry},
    };
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    fn unrestricted_context() -> Arc<crate::session_authorization::EffectiveAuthorizationContext> {
        let ceiling = SessionModeCeiling::for_trusted_sessions(
            [PermissionMode::Unrestricted],
            true,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .unwrap();
        SessionAuthorizationRegistry::with_ceiling(ceiling)
            .compatibility_context(PermissionMode::Unrestricted, None)
            .unwrap()
    }

    struct ProbeTool {
        definition: ToolDef,
        hits: Arc<AtomicUsize>,
        fail: bool,
    }

    #[async_trait]
    impl Tool for ProbeTool {
        fn def(&self) -> &ToolDef {
            &self.definition
        }

        async fn invoke(&self, _args: Value) -> ToolResult {
            self.hits.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                ToolResult::error("synthetic child failure")
                    .with_structured(json!({"code": "synthetic_failure"}))
            } else {
                ToolResult::text("synthetic child success")
            }
        }
    }

    fn probe(name: &str, schema: Value, hits: Arc<AtomicUsize>, fail: bool) -> ProbeTool {
        ProbeTool {
            definition: ToolDef {
                name: name.to_owned(),
                description: "test probe".to_owned(),
                input_schema: schema,
                read_only: false,
                destructive: false,
                idempotent: false,
                open_world: false,
            },
            hits,
            fail,
        }
    }

    struct StaticScreenshotTool {
        definition: ToolDef,
        paths: Arc<Mutex<Vec<PathBuf>>>,
        png: Vec<u8>,
    }

    #[async_trait]
    impl Tool for StaticScreenshotTool {
        fn def(&self) -> &ToolDef {
            &self.definition
        }

        async fn invoke(&self, args: Value) -> ToolResult {
            let path = PathBuf::from(args["screenshot_out_file"].as_str().unwrap());
            self.paths.lock().unwrap().push(path.clone());
            std::fs::write(&path, &self.png).unwrap();
            ToolResult::text("captured").with_structured(json!({
                "tree_included": false,
                "screenshot_file_path": path,
            }))
        }
    }

    fn solid_png(width: u32, height: u32) -> Vec<u8> {
        let image = image::DynamicImage::new_rgba8(width, height);
        let mut png = Vec::new();
        image
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        png
    }

    fn screenshot_probe(paths: Arc<Mutex<Vec<PathBuf>>>) -> StaticScreenshotTool {
        StaticScreenshotTool {
            definition: ToolDef {
                name: "get_window_state".to_owned(),
                description: "test screenshot probe".to_owned(),
                input_schema: json!({"type": "object"}),
                read_only: true,
                destructive: false,
                idempotent: false,
                open_world: false,
            },
            paths,
            png: solid_png(2, 2),
        }
    }

    #[test]
    fn fingerprint_uses_decoded_rgba_and_dimensions() {
        let first = image::DynamicImage::new_rgba8(2, 1);
        let second = image::DynamicImage::new_rgba8(1, 2);
        let mut first_png = Vec::new();
        let mut second_png = Vec::new();
        first
            .write_to(
                &mut std::io::Cursor::new(&mut first_png),
                image::ImageFormat::Png,
            )
            .unwrap();
        second
            .write_to(
                &mut std::io::Cursor::new(&mut second_png),
                image::ImageFormat::Png,
            )
            .unwrap();
        assert_ne!(
            decoded_pixel_fingerprint(&first_png).unwrap(),
            decoded_pixel_fingerprint(&second_png).unwrap()
        );
    }

    #[tokio::test]
    async fn batch_preflights_every_child_before_dispatch() {
        let hits = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(probe(
            "set_agent_cursor_enabled",
            json!({
                "type": "object",
                "required": ["enabled"],
                "properties": {"enabled": {"type": "boolean"}},
                "additionalProperties": false
            }),
            hits.clone(),
            false,
        )));
        registry.register_desktop_composite_tools(Arc::new(screenshot_probe(paths)));
        let registry = Arc::new(registry);
        registry.init_self_weak();

        let result = registry
            .invoke_with_context(
                "batch_actions",
                json!({"actions": [
                    {"tool": "set_agent_cursor_enabled", "arguments": {"enabled": true}},
                    {"tool": "missing_tool", "arguments": {}}
                ]}),
                unrestricted_context(),
            )
            .await;

        assert_eq!(result.is_error, Some(true));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn act_dispatches_child_once_and_cleans_private_baseline_on_error() {
        let hits = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(probe(
            "move_cursor",
            json!({
                "type": "object",
                "required": ["x", "y"],
                "properties": {
                    "x": {"type": "number"},
                    "y": {"type": "number"}
                },
                "additionalProperties": false
            }),
            hits.clone(),
            true,
        )));
        registry.register_desktop_composite_tools(Arc::new(screenshot_probe(paths.clone())));
        let registry = Arc::new(registry);
        registry.init_self_weak();
        let output = tempfile::tempdir().unwrap().path().join("final.png");

        let result = registry
            .invoke_with_context(
                "act_and_observe",
                json!({
                    "pid": 42,
                    "window_id": 7,
                    "screenshot_out_file": output,
                    "action": {
                        "tool": "move_cursor",
                        "arguments": {"x": 10, "y": 20}
                    }
                }),
                unrestricted_context(),
            )
            .await;

        assert_eq!(result.is_error, Some(true));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let baseline_path = paths.lock().unwrap()[0].clone();
        assert!(!baseline_path.parent().unwrap().exists());
    }
}
