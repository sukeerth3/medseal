# MedSeal Enclave Docker Image.
# This image is converted to an EIF (Enclave Image File) via nitro-cli.
# Keep it minimal and pinned to reduce PCR0 drift.

FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MEDSEAL_ENV=production \
    AWS_REGION=us-east-1 \
    AWS_DEFAULT_REGION=us-east-1 \
    KMS_KEY_ID=alias/medseal-master \
    VSOCK_PORT=5000 \
    KMS_PROXY_PORT=8000 \
    KMSTOOL_ENCLAVE_CLI=/usr/local/bin/kmstool-enclave-cli \
    LD_LIBRARY_PATH=/usr/lib:/usr/local/lib

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Official AWS Nitro Enclaves SDK for C KMS tool. scripts/build-kmstool.sh
# builds these artifacts from the pinned upstream release before EIF build.
COPY bin/kmstool_enclave_cli /usr/local/bin/kmstool-enclave-cli
COPY bin/libnsm.so /usr/lib/libnsm.so
RUN chmod 0755 /usr/local/bin/kmstool-enclave-cli /usr/lib/libnsm.so

COPY requirements.txt .
RUN pip install -r requirements.txt

# Pinned spaCy PHI model baked into the enclave image.
RUN pip install \
    https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

# Copy application code
COPY src/ ./src/

# The enclave has no network, no shell, no persistent storage.
# This is the only process that runs.
CMD ["/usr/local/bin/python3", "-c", "import sys; sys.path.insert(0, '/app'); from src.main import main; main()"]
