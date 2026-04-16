import subprocess
from pathlib import Path


def apply_patch_text(repo_root: str, patch_text: str) -> Path:
    patch_path = Path(repo_root) / "fix.patch"
    patch_path.write_text(patch_text, encoding="utf-8")
    proc = subprocess.run(
        ["git", "apply", "--unsafe-paths", str(patch_path.name)],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "git apply failed\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}\n"
            f"patch: {patch_path}"
        )
    return patch_path

