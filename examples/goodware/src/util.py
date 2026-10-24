"""yaraci lab fixture - synthetic and benign."""

import subprocess


def git_rev() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
