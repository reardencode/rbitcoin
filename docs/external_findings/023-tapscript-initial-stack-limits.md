# Tapscript initial witness stack skipped Core size limits (consensus split)

**Component:** `rbitcoin-consensus` (`script/interpreter.rs::eval_script` TapScript
branch)
**Severity:** **high — consensus split.** rbitcoin accepts a tapscript spend
Bitcoin Core rejects (`SCRIPT_ERR_STACK_SIZE` / `SCRIPT_ERR_PUSH_SIZE`).
**Status:** fixed — after the BIP342 OP_SUCCESS scan, tapscript checks
`stack.len() > MAX_STACK_SIZE` (1000) and every initial element
`<= MAX_SCRIPT_ELEMENT_SIZE` (520), matching Core `ExecuteWitnessScript`.
**Found by:** post-review of 022 (`MAX_STACK_SIZE` on PushBytes / TUCK)
**Regression:** `script::p2tr::bip341_tests::script_path_rejects_initial_stack_over_max_size`,
`script_path_rejects_initial_element_over_520`,
`script_path_op_success_overrides_initial_stack_limits`

## Summary

Core `ExecuteWitnessScript` (sigversion TAPSCRIPT) runs, after the OP_SUCCESS
scan and before eval:

```cpp
if (stack.size() > MAX_STACK_SIZE)
    return set_error(serror, SCRIPT_ERR_STACK_SIZE);
for (const valtype& elem : stack)
    if (elem.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
```

rbitcoin built the initial tapscript stack in `p2tr::verify_script_path` and
handed it to `eval_script` with neither check. `eval_script` already shares
stack+altstack against 1000 on later pushes (022), but that does not cover a
witness that arrives already oversized. A leaf of 1000 `OP_DROP` (or one
`OP_DROP` after a 521-byte element) would then succeed on rbitcoin and fail
on Core.

OP_SUCCESS must still override both limits (BIP342 / Core scan-before-size).

## Fix

In `eval_script`, immediately after the `tapscript_has_op_success` early
return: reject `stack.len() > 1000` (`stack size`) and any initial element
`> 520` (`PUSH_SIZE`). v0 witness paths are unchanged (`p2wsh` already
enforces the 520-byte check; Core has no initial *count* check for v0).
