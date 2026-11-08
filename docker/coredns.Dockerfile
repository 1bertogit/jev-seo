FROM --platform=linux/amd64 docker.io/coredns/coredns@sha256:3429e3bbffb1e839470c4a3541d4d78aca84a1394c75a539d0200c58c63196ac AS official

FROM --platform=linux/amd64 python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS inspector
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=official /coredns /work/coredns
RUN set -eux; \
    before=$(sha256sum /work/coredns | cut -d" " -f1); \
    before_cap=$(getcap -n /work/coredns || true); \
    printf "before_sha256=%s before_cap=%s\\n" "$before" "$before_cap"; \
    if [ -n "$before_cap" ]; then setcap -r /work/coredns; fi; \
    after=$(sha256sum /work/coredns | cut -d" " -f1); \
    after_cap=$(getcap -n /work/coredns || true); \
    printf "after_sha256=%s after_cap=%s\\n" "$after" "$after_cap"; \
    test "$before" = "$after"; \
    test -z "$after_cap"

FROM --platform=linux/amd64 docker.io/coredns/coredns@sha256:3429e3bbffb1e839470c4a3541d4d78aca84a1394c75a539d0200c58c63196ac AS final
COPY --from=inspector /work/coredns /coredns
