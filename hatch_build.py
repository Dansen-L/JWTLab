"""
Hatch build hook: runs `npm run build` inside frontend/ before wheel construction
and copies the resulting dist/ assets into jwtlab/static/.

This hook is the mechanism by which `pip install .` bundles the pre-built
React frontend into the Python wheel — end-users need no Node.js runtime.
Developer build-time requirement: Node 18+ and npm must be in PATH.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        project_root = Path(self.root)
        frontend_dir = project_root / "frontend"
        static_dir = project_root / "jwtlab" / "static"
        dist_dir = frontend_dir / "dist"

        # Skip if frontend source doesn't exist (e.g., during editable installs in CI)
        if not frontend_dir.exists():
            self.app.display_warning(
                "frontend/ directory not found — skipping npm build. "
                "Static assets will not be included in the wheel."
            )
            return

        # Check for npm
        npm_cmd = shutil.which("npm")
        if npm_cmd is None:
            self.app.display_warning(
                "npm not found in PATH — skipping frontend build. "
                "Install Node 18+ to build the frontend for distribution."
            )
            return

        # Install frontend dependencies if node_modules missing
        if not (frontend_dir / "node_modules").exists():
            self.app.display_info("Running npm install in frontend/...")
            result = subprocess.run(
                [npm_cmd, "install", "--silent"],
                cwd=str(frontend_dir),
                capture_output=False,
            )
            if result.returncode != 0:
                raise RuntimeError(f"npm install failed with code {result.returncode}")

        # Build the frontend
        self.app.display_info("Running npm run build in frontend/...")
        result = subprocess.run(
            [npm_cmd, "run", "build"],
            cwd=str(frontend_dir),
            capture_output=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"npm run build failed with code {result.returncode}")

        # Copy dist/ → jwtlab/static/
        if dist_dir.exists():
            if static_dir.exists():
                shutil.rmtree(static_dir)
            shutil.copytree(str(dist_dir), str(static_dir))
            self.app.display_info(f"Frontend assets copied to {static_dir}")
        else:
            raise RuntimeError(
                f"Expected frontend/dist/ after npm build, but {dist_dir} was not found."
            )
