#!/usr/bin/env python3
import os
import os.path
import signal
import subprocess
import sys
import time

env: dict[str, str] = {}
env["FAKE_DNS"] = (
    subprocess.check_output(  # noqa: S602
        r"ip addr show docker0 | awk 'match($0, /([0-9.]+)\/[0-9]+/, a) { print a[1] }'",  # noqa: S607
        shell=True,
    )
    .strip()
    .decode("utf-8")
)
if sys.argv[2] == "pebble":
    env["ACME_CAFILE"] = os.path.expanduser("~/build/letsencrypt/pebble/pebble.minica.pem")

if sys.argv[1] == "venv":
    server = subprocess.Popen(  # noqa: S603
        ["macen", f"configs/integration-{sys.argv[2]}.ini"],  # noqa: S607
        env={**os.environ, **env},
    )
else:
    subprocess.run(["docker", "build", "-t", "macen:latest", "."], check=True)  # noqa: S607
    server = subprocess.Popen(  # noqa: S603
        [  # noqa: S607
            "docker",
            "run",
            "--name=macen",
            "--network=pebble_acmenet",
            "--rm",
            "-v",
            "./configs:/configs",
            "-v",
            f"{os.path.expanduser('~/build/letsencrypt/pebble')}:{os.path.expanduser('~/build/letsencrypt/pebble')}",
            *[f"--env={name}={value}" for (name, value) in env.items()],
            "--publish=1313:1313",
            f"--publish={env['FAKE_DNS']}:5002:5002",
            "macen:latest",
            f"/configs/integration-docker-{sys.argv[2]}.ini",
        ]
    )
time.sleep(2)

try:
    subprocess.check_call("tests/integration/gencert.sh")  # noqa: S607
finally:
    if sys.argv[1] == "docker":
        server.send_signal(signal.SIGINT)
    else:
        server.terminate()
    server.wait(10)
    if not server.poll():
        server.kill()

subprocess.check_call(
    ["openssl", "x509", "-in", "tests/integration/work/domain-201512.pem", "-noout", "-text"]  # noqa: S607
)
subprocess.check_call(
    ["openssl", "x509", "-in", "tests/integration/work/domain-201512-2.pem", "-noout", "-text"]  # noqa: S607
)

subprocess.check_call(
    [  # noqa: S607
        "cmp",
        "tests/integration/work/domain-201512.pem",
        "tests/integration/work/domain-201512-2.pem",
    ]
)

subprocess.check_call(
    ["openssl", "x509", "-in", "tests/integration/work/dns-201512.pem", "-noout", "-text"]  # noqa: S607
)
