"""Exercise required statically linked providers with disposable local data."""

import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="boilstream-secret-providers-") as directory:
    result = subprocess.run([sys.argv[1], directory], timeout=60, check=False)
raise SystemExit(result.returncode)
