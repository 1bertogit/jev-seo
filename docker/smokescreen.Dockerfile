FROM --platform=linux/amd64 python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS fetch

RUN python - <<'PY'
import hashlib
import os
import posixpath
import tarfile
import urllib.request
from pathlib import Path

url = "https://github.com/stripe/smokescreen/releases/download/v0.1.0/smokescreen_v0.1.0_linux_amd64.tar.gz"
expected_size = 5313984
expected_sha256 = "4e1e447449e3cc653dae956208588722b5c8fe8ce894f633adc756a851d1ec46"
archive = Path("/tmp/smokescreen.tar.gz")
binary = Path("/tmp/smokescreen")
with urllib.request.urlopen(url, timeout=60) as response, archive.open("wb") as output:
    while chunk := response.read(1024 * 1024):
        output.write(chunk)
assert archive.stat().st_size == expected_size
assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected_sha256
target = "smokescreen_v0.1.0_linux_amd64/smokescreen"
with tarfile.open(archive, "r:gz") as tar:
    members = tar.getmembers()
    for member in members:
        assert not posixpath.isabs(member.name)
        assert ".." not in member.name.split("/")
        assert posixpath.normpath(member.name) == member.name
        assert not member.issym() and not member.islnk()
    matches = [member for member in members if member.name == target]
    assert len(matches) == 1 and matches[0].isreg()
    data = tar.extractfile(matches[0]).read()
assert data[:4] == b"\x7fELF"
binary.write_bytes(data)
os.chmod(binary, 0o755)
PY

FROM --platform=linux/amd64 python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
COPY --from=fetch /tmp/smokescreen /usr/local/bin/smokescreen
COPY docker/smokescreen.json /etc/smokescreen/smokescreen.json
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/smokescreen"]
CMD ["--config-file", "/etc/smokescreen/smokescreen.json", "--listen-ip", "127.0.0.1", "--listen-port", "4750"]
