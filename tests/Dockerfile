# syntax=docker/dockerfile:1
FROM ghcr.io/carlossg/maven:3.10.0-azulzulu-21@sha256:5d63a8f4281c21c53eb5978f63deaf939e53941b3f07dc383f1ef83f4f5807e4 AS java

FROM python:3.13.14-bookworm@sha256:8b9a8b28d9cc221c6ab5d40e9cfcd99429959f6a8f5171612a99147975ab043f
COPY --from=java /usr/lib/jvm/zulu21 /opt/java
ENV JAVA_HOME=/opt/java
ENV PATH="/opt/java/bin:${PATH}"
WORKDIR /workspace
COPY tests/conformance.py tests/conformance.py
COPY tests/fixtures tests/fixtures
COPY dist/java/dirhash.jar dist/java/dirhash.jar
COPY --chmod=0555 dist/go/dirhash-linux-amd64 dist/go/dirhash-linux-arm64 dist/go/
ENTRYPOINT ["python", "tests/conformance.py", "-v"]
