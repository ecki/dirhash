Runtime dependency notices
==========================

These original upstream legal files supplement runtime Maven JARs that do not
contain their own license resources. They are copied without filtering into
META-INF/licenses in dirhash.jar. Other runtime dependencies' own legal
resources are unpacked into artifact-specific directories before shading.
JUnit and other test/build-only dependencies are not redistributed.

Release-pinned sources and SHA-256 (original file bytes):

xz-1.10/COPYING
https://raw.githubusercontent.com/tukaani-project/xz-java/v1.10/COPYING
1e77ef26cee5216d6531e49cbf2f6111a0270dc7b322fc65477063c5aff88766
XZ for Java 1.10 is 0BSD; older public-domain descriptions do not apply.

zstd-jni-1.5.7-6/LICENSE
https://raw.githubusercontent.com/luben/zstd-jni/v1.5.7-6/LICENSE
289a6adada5726047b9e68bf607cc44fbbac953bbb4fd29f53ffe75b5cb3e7b1
JNI binding: BSD-2-Clause.

zstd-jni-1.5.7-6/ZSTANDARD-LICENSE
https://raw.githubusercontent.com/luben/zstd-jni/v1.5.7-6/src/main/native/LICENSE
2c1a7fa704df8f3a606f6fc010b8b5aaebf403f3aeec339a12048f1ba7331a0b
Bundled Zstandard: distributed using the BSD license option. Upstream offers
BSD or GPLv2, at the recipient's option, as stated in src/main/native/zstd.h:
https://raw.githubusercontent.com/luben/zstd-jni/v1.5.7-6/src/main/native/zstd.h
This distribution selects the BSD option, not GPLv2.
Current native source copyright also names Meta Platforms, Inc. and affiliates.

bcprov-jdk18on-1.82/LICENSE.html
https://raw.githubusercontent.com/bcgit/bc-java/r1rv82/LICENSE.html
edbbb10380b1271998b867a2e36b1cbee226e03d438726e1a91f80c5dde11849
Bouncy Castle license (MIT-style); retain the original upstream copyright.

icu4j-76.1/LICENSE
https://raw.githubusercontent.com/unicode-org/icu/release-76-1/LICENSE
01edac20612b1e590c1c1cfb02b7218c6adc7b0a944eda7a1e03aeee10725aed
Full ICU license, including its additional third-party notices and terms.

When updating dependencies, review these release-specific files and rerun the
artifact verifier. Presence and byte-preservation checks are not legal advice
or a substitute for reviewing changed upstream licensing.
