# Minimal, non-root, read-only-friendly image for an Aegis-governed agent.
# The hardening that matters is applied at RUNTIME (securityContext / docker
# run flags) — see k8s.yaml and the docker run example below — but the image
# is built to support it (non-root user, no shell tools it doesn't need).

FROM python:3.12-slim AS base

# Create an unprivileged user; the runtime also pins runAsUser=65532.
RUN useradd -u 65532 -m -s /usr/sbin/nologin agent

WORKDIR /app
COPY aegis/ /app/aegis/
RUN pip install --no-cache-dir cryptography

# Drop privileges in the image as well as at runtime.
USER 65532

# The policy bundle is NOT baked in — it is mounted read-only at /etc/aegis
# (signed) so it can be rotated without rebuilding and cannot be edited by the
# agent. The pinned pubkey is mounted alongside it.
ENV AEGIS_POLICY=/etc/aegis/policy.json \
    AEGIS_POLICY_SIG=/etc/aegis/policy.json.sig \
    AEGIS_PDP=http://aegis-pdp:8787

# Entrypoint is the agent; all its tool calls are brokered to the PDP.
ENTRYPOINT ["python", "-m", "your_agent"]

# Reference hardened `docker run` (equivalent to the k8s securityContext):
#   docker run --rm \
#     --read-only \
#     --user 65532:65532 \
#     --security-opt no-new-privileges \
#     --cap-drop ALL \
#     --security-opt seccomp=aegis/deploy/aegis-seccomp.json \
#     --pids-limit 128 --memory 512m --cpus 1 \
#     --network aegis-egress-only \
#     --tmpfs /scratch:rw,size=256m \
#     -v $PWD/bundle:/etc/aegis:ro \
#     governed-agent:pinned-digest
