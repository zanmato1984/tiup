#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Offline CLI acceptance test using only generated, disposable signing keys.

No fixture package is executed and no production mirror or credential is used.
The only HTTP requests go to this test's loopback server.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


def hashes(directory):
    return {
        str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.rglob("*")
        if p.is_file()
    }


def public_only(directory):
    assert not (directory / "keys").exists()
    for path in directory.glob("*.json"):
        assert '"private"' not in path.read_text(), path.name
    # Exercise exactly the documented public-only offline packaging boundary.
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(directory, arcname="mirror")
        buffer.seek(0)
        with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
            assert not any("keys" in Path(m.name).parts for m in archive.getmembers())


def main():
    tiup, server = (str(Path(p).resolve()) for p in sys.argv[1:3])
    with tempfile.TemporaryDirectory(prefix="tiup-key-layout-") as temporary:
        work = Path(temporary).resolve()
        source = work / "public"
        private = work / "public.keys"
        profile = work / "profile"
        (profile / "bin").mkdir(parents=True)
        env = dict(os.environ, TIUP_HOME=str(profile), TIUP_MIRRORS=str(source))
        # Do not inherit a developer's real deployment hooks or proxy routes.
        for name in list(env):
            if name == "TIUP_MIRROR_SYNC_SCRIPT" or name.lower().endswith("_proxy"):
                env.pop(name)
        env["TIUP_LOG_PATH"] = str(work / "logs")

        def run(*args, success=True):
            result = subprocess.run(
                [tiup, *map(str, args)], env=env, cwd=work,
                capture_output=True, text=True, timeout=60,
            )
            if (result.returncode == 0) != success:
                raise AssertionError(
                    f"Unexpected CLI result for {args}: {result.returncode}\n"
                    + result.stdout + result.stderr
                )
            return result

        run("mirror", "init", source)
        assert private.is_dir() and private.stat().st_mode & 0o777 == 0o700
        public_only(source)
        run("mirror", "set", source)
        run("mirror", "genkey")
        run("mirror", "grant", "pingcap")
        tarball = work / "inert.tar.gz"
        with tarfile.open(tarball, "w:gz") as archive:
            marker = b"inert test package; never executed\n"
            member = tarfile.TarInfo("marker.txt")
            member.size = len(marker)
            archive.addfile(member, io.BytesIO(marker))
        run("mirror", "publish", "marker", "v1.0.0", tarball, "marker.txt",
            "--os=linux", "--arch=amd64")
        clone = work / "clone"
        clone_private = work / "clone.keys"
        run("mirror", "clone", clone, "--os=linux", "--arch=amd64", "--marker=v1.0.0")
        public_only(clone)
        assert clone_private.is_dir()
        assert (clone / "marker-v1.0.0-linux-amd64.tar.gz").is_file()
        custom_clone = work / "custom-clone"
        custom_clone_keys = work / "custom-clone-private"
        run("mirror", "clone", custom_clone, "--os=linux", "--arch=amd64",
            "--marker=v1.0.0", "--key-dir", custom_clone_keys)
        public_only(custom_clone)
        assert custom_clone_keys.is_dir()
        original_clone_keys = hashes(clone_private)
        run("mirror", "clone", clone, "--os=linux", "--arch=amd64", success=False)
        assert hashes(clone_private) == original_clone_keys
        bad = work / "bad"
        run("mirror", "init", bad, "--key-dir", bad / "keys", success=False)
        assert not (bad / "keys").exists()

        # Simulate an old mirror. Migration must work even with a currently
        # configured legacy mirror: root pre-run must not initialize it first.
        public_before, keys_before = hashes(source), hashes(private)
        old_key_names = list(keys_before)
        private.rename(source / "keys")
        rejected = subprocess.run(
            [server, str(source), "--upstream="], env=env,
            capture_output=True, text=True, timeout=10,
        )
        assert rejected.returncode != 0 and "migrate-keys" in rejected.stdout + rejected.stderr
        run("mirror", "migrate-keys", source)
        assert hashes(source) == public_before
        assert hashes(private / "keys") == keys_before
        for path in private.rglob("*"):
            assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
        public_only(source)
        run("mirror", "genkey", "--name=after-migration")
        run("mirror", "grant", "after-migration", "--key", profile / "keys/after-migration.json")

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen(
            [server, str(source), f"--addr=127.0.0.1:{port}", "--upstream="],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 10
            while True:
                try:
                    with urllib.request.urlopen(base + "/root.json", timeout=1) as response:
                        assert "roles" in json.load(response)["signed"]
                    break
                except urllib.error.URLError:
                    assert process.poll() is None, "test server exited before startup"
                    assert time.monotonic() < deadline, "test server did not start"
                    time.sleep(0.05)
            for name in old_key_names:
                try:
                    urllib.request.urlopen(base + "/keys/" + name, timeout=2)
                    raise AssertionError("private path was unexpectedly available")
                except urllib.error.HTTPError as error:
                    assert error.code == 403
        finally:
            process.terminate()
            process.wait(timeout=10)

        # A custom destination is propagated to signing consumers, not just init.
        custom = work / "custom"
        custom_keys = work / "custom-private"
        run("mirror", "init", custom, "--key-dir", custom_keys)
        run("mirror", "set", custom)
        env["TIUP_MIRRORS"] = str(custom)
        run("mirror", "grant", "custom-owner", "--key-dir", custom_keys)
        public_only(custom)
        run("mirror", "set", clone)
        env["TIUP_MIRRORS"] = str(clone)
        run("list", "marker")  # Validate cloned manifests without executing the marker.
        print("PASS: default/custom init, signing, package clone, public-only archive, "
              "legacy startup rejection, identity-preserving migration and loopback HTTP")


if __name__ == "__main__":
    main()
