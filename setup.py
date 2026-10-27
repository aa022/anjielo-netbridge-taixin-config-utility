"""Setuptools hook that compiles the host-specific C shared library."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.build_py import build_py

# The Makefile owns the base compile flags; this marker names that line.
CFLAGS_MARKER = "BASE_CFLAGS :="


def read_base_cflags(makefile: Path) -> list[str]:
    for line in makefile.read_text(encoding="utf-8").splitlines():
        if line.startswith(CFLAGS_MARKER):
            return shlex.split(line[len(CFLAGS_MARKER):])
    raise RuntimeError(f"{makefile} does not define {CFLAGS_MARKER.strip()}")


class BuildPyWithNative(build_py):
    def run(self) -> None:
        super().run()
        root = Path(__file__).parent.resolve()
        output_directory = Path(self.build_lib) / "ah_netbridge" / "_native"
        output_directory.mkdir(parents=True, exist_ok=True)
        suffix = ".dylib" if sys.platform == "darwin" else ".so"
        output = output_directory / f"libtaixinnet{suffix}"
        compiler = os.environ.get("CC", "cc")
        command = [compiler]
        command += read_base_cflags(root / "Makefile")
        command += ["-I", str(root / "include")]
        command += ["-dynamiclib"] if sys.platform == "darwin" else ["-shared"]
        command += ["-o", str(output), str(root / "native" / "taixinnet.c")]
        self.spawn(command)


class PlatformDistribution(Distribution):
    """Mark wheels as platform-specific because they contain compiled code."""

    def has_ext_modules(self) -> bool:
        return True


setup(cmdclass={"build_py": BuildPyWithNative}, distclass=PlatformDistribution)
