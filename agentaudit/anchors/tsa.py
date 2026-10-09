"""M2: RFC 3161 trusted timestamps, using the OpenSSL command line.

Two interchangeable transports produce timestamp replies:
  LocalTSA  - a self-contained OpenSSL timestamp authority (tests, offline runs)
  HttpTSA   - a real public authority such as freeTSA (needs its CA certificate file)
Timestamp tokens are kept in an escrow directory that models an off-host copy.
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request

from . import MissingDependency, Receipt, anchor_bytes
from ..events import Anchor

TSA_CNF = """[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir = .
serial = $dir/tsaserial
crypto_device = builtin
signer_cert = $dir/tsa.crt
certs = $dir/tsa.crt
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.5
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""

_WINDOWS_OPENSSL_CANDIDATES = [
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    r"C:\Program Files\FireDaemon OpenSSL 3\bin\openssl.exe",
]


def find_openssl() -> str:
    """Locate the openssl executable: OPENSSL_BIN, then PATH, then common Windows locations."""
    env = os.environ.get("OPENSSL_BIN")
    if env:
        if os.path.isfile(env):
            return env
        raise MissingDependency(f"OPENSSL_BIN is set to {env!r} but that file does not exist")
    found = shutil.which("openssl")
    if found:
        return found
    for cand in _WINDOWS_OPENSSL_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    raise MissingDependency(
        "openssl was not found. Install it (Windows: install Git for Windows, which includes "
        "openssl.exe, or run 'winget install ShiningLight.OpenSSL.Light'), then either add its "
        "folder to PATH or set the OPENSSL_BIN environment variable to the full path of openssl.exe."
    )


def _run(args, cwd=None):
    if args and args[0] == "openssl":
        args = [find_openssl()] + list(args[1:])
    return subprocess.run(args, cwd=cwd, capture_output=True)


class LocalTSA:
    """A throwaway timestamp authority backed by `openssl ts -reply`."""

    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "tsa.cnf"), "w") as f:
            f.write(TSA_CNF)
        with open(os.path.join(directory, "tsaserial"), "w") as f:
            f.write("01\n")
        r = _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                  "-keyout", "tsa.key", "-out", "tsa.crt", "-days", "365",
                  "-subj", "/CN=Local Test TSA",
                  "-addext", "extendedKeyUsage=critical,timeStamping",
                  "-addext", "keyUsage=critical,digitalSignature"], cwd=directory)
        if r.returncode != 0:
            raise RuntimeError("could not create TSA certificate: " + r.stderr.decode())
        self.ca_file = os.path.join(directory, "tsa.crt")

    def reply(self, query: bytes) -> bytes:
        qpath = os.path.join(self.dir, "q.tsq")
        rpath = os.path.join(self.dir, "r.tsr")
        with open(qpath, "wb") as f:
            f.write(query)
        r = _run(["openssl", "ts", "-reply", "-config", "tsa.cnf", "-queryfile", "q.tsq",
                  "-out", "r.tsr"], cwd=self.dir)
        if r.returncode != 0:
            raise RuntimeError("timestamp reply failed: " + r.stderr.decode())
        with open(rpath, "rb") as f:
            return f.read()


class HttpTSA:
    """Talks to a public RFC 3161 server, e.g. https://freetsa.org/tsr (use freeTSA's cacert.pem)."""

    def __init__(self, url: str, ca_file: str, timeout: float = 20.0):
        self.url, self.ca_file, self.timeout = url, ca_file, timeout

    def reply(self, query: bytes) -> bytes:
        req = urllib.request.Request(
            self.url, data=query, headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read()


class TimestampAnchorer:
    name = "M2-timestamp"

    def __init__(self, transport, escrow_dir: str, untrusted_file: str = None):
        self.transport = transport
        self.ca_file = transport.ca_file
        self.untrusted = untrusted_file
        self.escrow = escrow_dir
        os.makedirs(escrow_dir, exist_ok=True)
        self._n = len([f for f in os.listdir(escrow_dir) if f.endswith(".json")])

    def _verify_args(self):
        args = ["-CAfile", self.ca_file]
        if self.untrusted:
            args += ["-untrusted", self.untrusted]
        return args

    def publish(self, anchor: Anchor) -> Receipt:
        t0 = time.perf_counter()
        digest = hashlib.sha256(anchor_bytes(anchor)).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            qp = os.path.join(tmp, "req.tsq")
            rp = os.path.join(tmp, "resp.tsr")
            q = _run(["openssl", "ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", qp])
            if q.returncode != 0:
                raise RuntimeError("timestamp query failed: " + q.stderr.decode())
            with open(qp, "rb") as f:
                query = f.read()
            reply = self.transport.reply(query)
            with open(rp, "wb") as f:
                f.write(reply)
            v = _run(["openssl", "ts", "-verify", "-in", rp, "-queryfile", qp] + self._verify_args())
            if v.returncode != 0:
                raise RuntimeError("timestamp reply did not verify: " + (v.stderr + v.stdout).decode())
        stem = os.path.join(self.escrow, f"{self._n:06d}")
        with open(stem + ".tsr", "wb") as f:
            f.write(reply)
        with open(stem + ".json", "w") as f:
            json.dump({"length": anchor.length, "head": anchor.head_hash}, f)
        self._n += 1
        return Receipt(self.name, time.perf_counter() - t0, {"bytes": len(reply)}, ref=os.path.basename(stem))

    def published(self) -> list:
        """Anchors whose stored token verifies against the TSA certificate AND matches the anchor."""
        out = []
        for name in sorted(f for f in os.listdir(self.escrow) if f.endswith(".json")):
            stem = os.path.join(self.escrow, name[:-5])
            try:
                with open(stem + ".json") as f:
                    obj = json.load(f)
                anchor = Anchor(length=obj["length"], head_hash=obj["head"])
            except (OSError, ValueError, KeyError):
                continue
            digest = hashlib.sha256(anchor_bytes(anchor)).hexdigest()
            v = _run(["openssl", "ts", "-verify", "-in", stem + ".tsr", "-digest", digest,
                      "-sha256"] + self._verify_args())
            if v.returncode == 0:
                out.append(anchor)
        return out
