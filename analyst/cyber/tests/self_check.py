from pathlib import Path
import py_compile
import sys

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "run.py",
    "requirements.txt",
    "app/__init__.py",
    "app/routes.py",
    "app/db.py",
    "app/services/event_processor.py",
    "app/services/simulator.py",
    "app/services/ai.py",
]

missing = [
    file for file in REQUIRED
    if not (ROOT / file).exists()
]

errors = []

# Only check OUR source directories.
# Do not scan .venv or installed third-party packages.
source_dirs = [
    ROOT / "app",
    ROOT / "ml",
    ROOT / "simulations",
    ROOT / "tests",
]

for directory in source_dirs:
    if not directory.exists():
        continue

    for path in directory.rglob("*.py"):
        # Never inspect virtual-environment files.
        if ".venv" in path.parts:
            continue

        try:
            py_compile.compile(
                str(path),
                doraise=True
            )
        except Exception as exc:
            errors.append((str(path), str(exc)))

# Check run.py separately
try:
    py_compile.compile(
        str(ROOT / "run.py"),
        doraise=True
    )
except Exception as exc:
    errors.append((str(ROOT / "run.py"), str(exc)))


if missing or errors:
    print("FAIL")
    print("Missing:", missing)
    print("Syntax:", errors)
    sys.exit(1)

print("PASS: required project files are present and Python syntax is valid.")