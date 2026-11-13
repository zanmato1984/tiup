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

"""Exercise existing signing layouts against a loopback-only patched server.

All keys are disposable fixtures. The inert test package is never executed.
No deployment, proxy, production credential or remote mirror is used.
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
        for p in directory.rglob("*") if p.is_file()
    }


def main():
    tiup, server = (str(Path(p).resolve()) for p in sys.argv[1:3])
    with tempfile.TemporaryDirectory(prefix="tiup-server-private-files-") as temporary:
        for layout in ("default", "custom", "external"):
            work = Path(temporary) / layout
            root, profile = work / "mirror", work / "profile"
            (profile / "bin").mkdir(parents=True)
            (work / "server-data").mkdir()
            env = dict(os.environ, TIUP_HOME=str(profile), TIUP_MIRRORS=str(root))
            for name in list(env):
                if name == "TIUP_MIRROR_SYNC_SCRIPT" or name.lower().endswith("_proxy"):
                    env.pop(name)
            env["TIUP_LOG_PATH"] = str(work / "logs")
            env["TIUP_COMPONENT_DATA_DIR"] = str(work / "server-data")

            def run(*args, mirror=None):
                active = dict(env, TIUP_MIRRORS=mirror or str(root))
                result = subprocess.run(
                    [tiup, *map(str, args)], env=active, cwd=work,
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode:
                    raise AssertionError(
                        f"CLI failed ({layout}, {args}): {result.returncode}\n"
                        + result.stdout + result.stderr
                    )

            run("mirror", "init", root)
            keys = root / "keys"
            assert keys.is_dir(), "init must retain the existing layout"
            assert not root.with_name("mirror.keys").exists()
            run("mirror", "set", root)
            run("mirror", "genkey")
            run("mirror", "grant", "pingcap")
            before = hashes(keys)
            if layout != "default":
                selected = root / "private-signing" if layout == "custom" else work / "private"
                keys.rename(selected)
                keys = selected
                # A configured custom store must not expose leftover default keys.
                (root / "keys").mkdir()
                (root / "keys" / "legacy.json").write_text("LEGACY PRIVATE MARKER")

            tarball = work / "inert.tar.gz"
            with tarfile.open(tarball, "w:gz") as archive:
                marker = b"inert package; never executed\n"
                member = tarfile.TarInfo("marker.txt")
                member.size = len(marker)
                archive.addfile(member, io.BytesIO(marker))

            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            args = [server, str(root), f"--addr=127.0.0.1:{port}", "--upstream="]
            if layout != "default":
                args += ["--key-dir", str(keys)]
            process = subprocess.Popen(
                args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            base = f"http://127.0.0.1:{port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with opener.open(base + "/root.json", timeout=1) as response:
                            assert "roles" in json.load(response)["signed"]
                        break
                    except urllib.error.URLError:
                        assert process.poll() is None, f"server exited for {layout} layout"
                        assert time.monotonic() < deadline, "server startup timed out"
                        time.sleep(0.05)

                # Real publishing exercises role keys loaded from each existing
                # location, while the HTTP checks never emit private response bytes.
                run("mirror", "publish", "marker", "v1.0.0", tarball, "marker.txt",
                    "--os=linux", "--arch=amd64", mirror=base)
                run("list", "marker", mirror=base)
                with opener.open(base + "/marker-v1.0.0-linux-amd64.tar.gz", timeout=2) as response:
                    assert response.read() == tarball.read_bytes()

                denied = ["/keys/missing.json", "/KEYS/missing.json"]
                if layout == "default":
                    denied += ["/keys/" + name for name in before]
                elif layout == "custom":
                    denied += ["/private-signing/" + name for name in before]
                    denied += ["/keys/legacy.json"]
                else:
                    denied += ["/keys/legacy.json"]
                for path in denied:
                    try:
                        with opener.open(base + path, timeout=2) as response:
                            raise AssertionError(f"Private path returned {response.status}: {path}")
                    except urllib.error.HTTPError as error:
                        assert error.code == 403, (layout, path, error.code)
            finally:
                process.terminate()
                process.wait(timeout=10)

            if layout == "default":
                run("mirror", "publish", "marker", "v1.0.1", tarball, "marker.txt",
                    "--os=linux", "--arch=amd64")
                run("list", "marker")
            assert hashes(keys) == before, "serving/publishing must not move or replace keys"
            assert not root.with_name("mirror.keys").exists()
            print(f"PASS: {layout} keys retained, server signing works, private HTTP denied")


if __name__ == "__main__":
    main()
