#!/usr/bin/env python3
"""Actual tenant session quota and registry ownership; no native database or JWT qualification."""
import argparse, hashlib, json, pathlib, subprocess
p = argparse.ArgumentParser()
p.add_argument('--output', required=True)
p.add_argument('--cxx', required=True)
a = p.parse_args()
out = pathlib.Path(a.output)
assert out.is_absolute() and not out.exists() and pathlib.Path(a.cxx).is_absolute()
out.mkdir()
root = pathlib.Path(__file__).resolve().parent.parent
files = [root/'src/include/quack_tenant_session_quota.hpp', root/'src/include/quack_session_admission_registry.hpp', root/'test/cpp/quack_tenant_session_quota_probe.cpp', pathlib.Path(__file__)]
receipt = {'scope': __doc__, 'status': 'not_run', 'hashes': {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}}
try:
    binary = out/'probe'
    command = [a.cxx, '-std=c++17', '-pthread', '-Wall', '-Wextra', '-Werror', '-I'+str(root/'src/include'), str(files[2]), '-o', str(binary)]
    built = subprocess.run(command, capture_output=True, text=True, timeout=30)
    (out/'compile.log').write_text(built.stdout+built.stderr)
    assert built.returncode == 0, built.stderr
    ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    (out/'run.log').write_text(ran.stdout+ran.stderr)
    assert ran.returncode == 0, ran.stdout+ran.stderr
    receipt.update(status='PASS', command=command, observation=ran.stdout)
    print(ran.stdout.strip())
finally:
    (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
