use std::path::PathBuf;
use std::process::Command;

fn python_contract(script: &str) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .args(["-c", script])
        .current_dir(root)
        .output()
        .expect("Python is required for the native C fixture contract");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn pending_read_gate_counts_the_real_inline_mpr_read() {
    python_contract(
        r#"
from pathlib import Path
import subprocess

shell = Path('tests/native/mup_provider/run_kernel_only.sh').read_text()
lines = [line for line in shell.splitlines()
         if "grep -Eq" in line and 'mup-provider-read-pending-complete' in line]
assert len(lines) == 1, 'one authoritative pending READ counter gate required'
pattern = lines[0].split("'")[1]
def admitted(count, size):
    result = subprocess.run(['grep', '-E', pattern], text=True, capture_output=True,
        input=f'[mup-provider-read-pending-complete] count={count} bytes={size}\n')
    assert result.returncode in (0, 1), result.stderr
    return result.returncode == 0
assert admitted(3, 30), 'MPR READ + inline READ + pending READ must admit count=3 bytes=30'
for count, size in ((2, 20), (2, 30), (4, 30), (3, 20), (3, 40)):
    assert not admitted(count, size), f'incorrect cumulative READ evidence admitted: {count}/{size}'
assert 'grep -Fc' in shell and "'[mup-provider-read-pending-complete]'" in shell
assert '"$RUN_LOG")" -ne 1' in shell, 'pending completion must remain unique'
"#,
    );
}

#[test]
fn inline_mpr_constructs_a_real_read_before_both_forwarded_reads() {
    python_contract(
        r#"
import json
import os
from pathlib import Path
import subprocess

def walk(node):
    yield node
    for child in node.get('inner', []):
        yield from walk(child)
def callee(node):
    refs = [n.get('referencedDecl', {}).get('name')
            for part in node.get('inner', [])[:1] for n in walk(part)
            if n.get('kind') == 'DeclRefExpr']
    return refs[0] if refs else None
result = subprocess.run([os.environ.get('CLANG', 'clang'),
    '--target=x86_64-pc-windows-msvc', '-fms-extensions', '-ffreestanding',
    '-fno-builtin', '-fno-stack-protector', '-mno-stack-arg-probe', '-fno-ident',
    '-Wall', '-Wextra', '-Werror', '-O2', '-fsyntax-only', '-Xclang', '-ast-dump=json',
    'tests/native/mup_provider/read_forward.c'], capture_output=True, text=True, check=True)
ast = json.loads(result.stdout)
functions = {n['name']: n for n in ast.get('inner', [])
             if n.get('kind') == 'FunctionDecl'
             and any(c.get('kind') == 'CompoundStmt' for c in n.get('inner', []))}
mpr = functions['CheckInlineMpr']
assignments = [n for n in walk(mpr) if n.get('kind') == 'BinaryOperator' and n.get('opcode') == '=']
def assigns(member, value):
    return any(any(n.get('kind') == 'MemberExpr' and n.get('name') == member
                   for n in walk(a['inner'][0]))
               and any(n.get('kind') == 'IntegerLiteral' and n.get('value') == str(value)
                       for n in walk(a['inner'][1])) for a in assignments)
assert assigns('MajorFunction', 3), 'MPR must issue actual IRP_MJ_READ'
assert assigns('ByteOffset', 0), 'MPR must exercise the ordinary immediate READ'
calls = [callee(n) for n in walk(mpr) if n.get('kind') == 'CallExpr']
assert calls.count('IofCallDriver') == 1 and calls.count('IofCompleteRequest') == 1
assert calls.index('IofCallDriver') < calls.index('IofCompleteRequest')
sequences = []
for function in functions.values():
    calls = [n for n in walk(function) if n.get('kind') == 'CallExpr'
             and callee(n) in ('CheckInlineMpr', 'ForwardOnce')]
    if any(callee(n) == 'CheckInlineMpr' for n in calls):
        sequences.append(calls)
assert len(sequences) == 1
sequence = sequences[0]
assert [callee(n) for n in sequence] == ['CheckInlineMpr', 'ForwardOnce', 'ForwardOnce']
for call, offset in zip(sequence[1:], (0, 1)):
    actual = [n['value'] for n in walk(call['inner'][-1]) if n.get('kind') == 'IntegerLiteral']
    assert actual == [str(offset)], 'MPR must precede inline offset0 and pending offset1 READs'
"#,
    );
}

#[test]
fn split_terminal_intent_and_mpr_receipts_are_not_native_proof() {
    python_contract(
        r#"
import sys
sys.path.insert(0, 'tests/native/mup_provider')
from test_verify_log import primary_lines
from verify_log import verify_primary_execution

lines = primary_lines()
verify_primary_execution('\n'.join(lines))
targets = [i for i, line in enumerate(lines)
           if line.startswith('[inline-mpr-')
           or line.startswith('[mup-terminal-failure-terminal-intent]')]
assert len(targets) == 8
for index in targets:
    line = lines[index]
    cut = line.index(']') // 2
    corruptions = (
        ['[fsd-active-write] after-call ' + line],
        [line[:cut] + '[fsd-active-write] after-call status=0', line[cut:]],
    )
    for replacement in corruptions:
        changed = lines[:index] + replacement + lines[index + 1:]
        try:
            verify_primary_execution('\n'.join(changed))
        except ValueError:
            pass
        else:
            raise AssertionError(f'interleaved receipt incorrectly accepted: {line}')
"#,
    );
}
