#!/usr/bin/env python3
"""Run clang-tidy on every extension translation unit; reject empty/partial scans."""
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
build = Path(sys.argv[1]).resolve()
commands = json.loads((build / 'compile_commands.json').read_text())
source_list = re.search(r'set\(EXTENSION_SOURCES\s+([^)]*)\)', (root / 'CMakeLists.txt').read_text())
if not source_list:
    raise SystemExit('Cannot identify the production extension source list')
expected = {(root / name).resolve() for name in source_list.group(1).split()}
if any(not p.is_file() or p.suffix != '.cpp' for p in expected):
    raise SystemExit('Unrecognized production source list; update the coverage check')
compiled = {
    (Path(entry['directory']) / entry['file']).resolve() for entry in commands
}
missing = expected - compiled
if not expected or missing:
    raise SystemExit('Incomplete clang-tidy coverage: ' + ', '.join(map(str, sorted(missing))))
# Apple Clang finds SDK headers through its driver. A separately installed
# clang-tidy does not, so supply the selected SDK explicitly on local macOS.
# Keep Linux/community CI unchanged and preserve explicit caller overrides.
sdk_args = []
if sys.platform == 'darwin' and not any('isysroot' in arg for arg in sys.argv[2:]):
    cache = (build / 'CMakeCache.txt').read_text()
    selected = re.search(r'^CMAKE_OSX_SYSROOT:[^=]+=(.*)$', cache, re.MULTILINE)
    sdk = selected.group(1) if selected else ''
    if not Path(sdk).is_absolute():
        command = ['xcrun'] + (['--sdk', sdk] if sdk else []) + ['--show-sdk-path']
        sdk = subprocess.check_output(command, text=True).strip()
    headers = Path(sdk) / 'usr/include/c++/v1'
    if not (headers / 'cstddef').is_file():
        raise SystemExit('Selected macOS SDK lacks C++ headers: ' + str(headers))
    sdk_args = ['-extra-arg=-isysroot', '-extra-arg=' + sdk,
                '-extra-arg=-isystem', '-extra-arg=' + str(headers)]
pattern = '^' + re.escape(str(root / 'src')) + r'/.*[.]cpp$'
print(f'Checking all {len(expected)} extension translation units', flush=True)
subprocess.run([
    sys.executable, str(root / 'duckdb/scripts/run-clang-tidy.py'),
    '-p', str(build), pattern, '-header-filter', '^' + re.escape(str(root / 'src')) + '/',
    '-quiet', *sdk_args, *sys.argv[2:],
], check=True)
