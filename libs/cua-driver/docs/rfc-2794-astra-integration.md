# RFC #2794: GPT-6 Astra programmatic integration

This note extends [RFC #2794](https://github.com/trycua/cua/issues/2794) with a
model-agnostic pattern for agent-side programmatic integration. It does not
add arbitrary code execution to Cua Driver.

## Boundary

The integration has four layers:

1. GPT-6 Astra may generate a bounded JavaScript program through OpenAI
   Programmatic Tool Calling. The hosted V8 has no Node.js, filesystem, or
   network access.
2. The program can call one strict function, `cua_call(tool, arguments_json)`.
   Its explicit allowlist contains reversible desktop input and observation
   operations, including `act_and_observe` and `batch_actions`. It excludes
   launch, kill, browser, clipboard, recording/replay, configuration, and raw
   button-down/up operations.
3. `cua_call` forwards each admitted invocation to the ordinary Cua MCP
   server. It cannot create a grant, bypass policy, or suppress a child
   refusal.
4. Cua Driver performs composite preflight and dispatches every child through
   `ToolRegistry::invoke`, preserving the canonical authorization and result
   path.

The function accepts child arguments as a bounded JSON string so its own input
schema remains strict while each selected Cua tool remains responsible for its
exact live schema. Its output is the closed envelope
`{ok, result_json, error_code}`. Oversized results are replaced with a bounded
error directing the program to use `query`, `max_elements`, or a narrower
operation.

## Latency ownership

- `batch_actions` removes local process/transport round trips for a known
  ordered sequence.
- `act_and_observe` removes the race and extra model turn between one action
  and its changed-frame observation.
- Programmatic Tool Calling removes model turns between dependent driver calls
  that still need JavaScript branching or aggregation.
- The desktop and MCP processes remain persistent across model responses; the
  hosted JavaScript environment may be fresh for each program.

This separation keeps general code execution in the agent runtime and bounded
desktop mechanics in the driver. It also permits clients without Astra or
Programmatic Tool Calling to use the same driver tools directly.

## Linux deployment guidance

An application that needs the RFC's identified per-window polling on a
Wayland desktop can run the controlled target through XWayland and use the X11
driver path for structured actions, window zoom, MIT-SHM capture, and pixel
polling. A separate native-Wayland MCP process may retain full-display
grounding for native surfaces. This split is useful while identified
native-Wayland per-window capture remains an explicit RFC non-goal.

This integration pattern does not replace the RFC's required controlled
25-sample benchmark or platform-specific macOS and Windows evidence.

## References

- [GPT-6 Astra model](https://developers.openai.com/api/docs/models/gpt-6-astra)
- [Computer use](https://developers.openai.com/api/docs/guides/tools-computer-use)
- [Programmatic Tool Calling](https://developers.openai.com/api/docs/guides/tools-programmatic-tool-calling)
