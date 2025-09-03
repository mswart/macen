#!/usr/bin/env python3
import os
import os.path
import subprocess
import sys
import time

if sys.argv[1] == "generic":
    # we do not have any ACME server as backend
    sys.exit(0)

env = dict(os.environ)
env["FAKE_DNS"] = (
    subprocess.check_output(  # noqa: S602
        r"ip addr show docker0 | awk 'match($0, /([0-9.]+)\/[0-9]+/, a) { print a[1] }'",  # noqa: S607
        shell=True,
    )
    .strip()
    .decode("utf-8")
)
if sys.argv[1] == "pebble":
    env["ACME_CAFILE"] = os.path.expanduser("~/build/letsencrypt/pebble/pebble.minica.pem")

server = subprocess.Popen(["macen", "configs/integration-{}.ini".format(sys.argv[1])], env=env)  # noqa: S603, S607
time.sleep(2)

try:
    subprocess.check_call("tests/integration/gencert.sh")  # noqa: S607
finally:
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
