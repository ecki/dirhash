# syntax=docker/dockerfile:1
ARG MAVEN_IMAGE=ghcr.io/carlossg/maven:3.10.0-azulzulu-21@sha256:5d63a8f4281c21c53eb5978f63deaf939e53941b3f07dc383f1ef83f4f5807e4
FROM ${MAVEN_IMAGE} AS build
WORKDIR /src
COPY pom.xml .
COPY src src
COPY licenses licenses
COPY packaging packaging
COPY --from=project-license LICENSE /LICENSE
COPY --from=project-license NOTICE /NOTICE
COPY --from=test-vectors . /test-vectors
ENV DIRHASH_TEST_VECTORS=/test-vectors
RUN --mount=type=cache,target=/root/.m2 \
    mvn --batch-mode --no-transfer-progress verify \
    && java packaging/VerifyLicenses.java target/dirhash.jar target/license-dependencies licenses /LICENSE /NOTICE \
    && java -jar target/dirhash.jar --version \
    && java -jar target/dirhash.jar --help

RUN set -eu; \
    java -jar target/dirhash.jar --help >target/cli.stdout 2>target/cli.stderr; \
    grep -Fq "Usage: dirhash [options] INPUT" target/cli.stdout; \
    grep -Fq "ZIP methods:" target/cli.stdout; \
    test ! -s target/cli.stderr; \
    java -jar target/dirhash.jar --version >target/cli.stdout 2>target/cli.stderr; \
    grep -Fxq "dirhash 0.1.0-SNAPSHOT" target/cli.stdout; \
    test ! -s target/cli.stderr; \
    if java -jar target/dirhash.jar >target/cli.stdout 2>target/cli.stderr; then exit 1; else test "$?" -eq 2; fi; \
    test ! -s target/cli.stdout; \
    grep -Fq "USAGE:" target/cli.stderr; \
    mkdir target/smoke-empty; \
    java -jar target/dirhash.jar --h1 --gittree --nar --format=json target/smoke-empty \
        >target/cli.stdout 2>target/cli.stderr; \
    grep -Fq '"schemaVersion":1,"results":[' target/cli.stdout; \
    grep -Fq 'h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' target/cli.stdout; \
    grep -Fq '4b825dc642cb6eb9a060e54bf8d69288fbee4904' target/cli.stdout; \
    test ! -s target/cli.stderr; \
    if java -jar target/dirhash.jar --h1:invalid target/smoke-empty >target/cli.stdout 2>target/cli.stderr; then exit 1; else test "$?" -eq 2; fi; \
    test ! -s target/cli.stdout; \
    grep -Fq "USAGE:" target/cli.stderr; \
    rmdir target/smoke-empty

FROM scratch AS artifacts
COPY --from=build /src/target/dirhash.jar /dirhash.jar
COPY --from=build /LICENSE /LICENSE
COPY --from=build /NOTICE /NOTICE
