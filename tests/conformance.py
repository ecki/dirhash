"""Black-box conformance tests for both packaged dirhash implementations."""

import argparse
import base64
import contextlib
import gzip
import hashlib
import http.server
import io
import json
import lzma
import os
from pathlib import Path
import platform
import random
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import warnings
import zipfile
import zlib


ROOT = Path(__file__).resolve().parent.parent
SCHEMES = ("h1", "h1-go", "gittree", "swhid", "nar")
DIGESTS = (
    "sha1", "sha256", "sha512", "blake2b-256",
    "blake2b-512", "blake3", "sha3-256", "sha3-512",
)
COMMON_FLAGS = ["--h1", "--gittree", "--gittree:sha256", "--swhid", "--nar"]
FIXTURES = ROOT / "tests" / "fixtures"


def digest(algorithm, payload):
    if algorithm.startswith("blake2b-"):
        return hashlib.blake2b(payload, digest_size=int(algorithm[8:]) // 8).digest()
    return hashlib.new(algorithm.replace("-", "_"), payload).digest()


def tree_with_parents(entries):
    result = dict(entries)
    for path in list(result):
        parent = path.rpartition("/")[0]
        while parent:
            result.setdefault(parent, ("dir", b"", 0o755))
            parent = parent.rpartition("/")[0]
    return result


def nar_string(data):
    return struct.pack("<Q", len(data)) + data + bytes((-len(data)) % 8)


def nar_bytes(entries):
    tree = tree_with_parents(entries)

    def token(value):
        return nar_string(value.encode("ascii"))

    def node(path, kind, data, mode):
        parts = [token("("), token("type")]
        if kind == "dir":
            parts.append(token("directory"))
            prefix = path + "/" if path else ""
            children = [
                name for name in tree
                if name.startswith(prefix) and "/" not in name[len(prefix):]
            ]
            for name in sorted(children, key=lambda p: p[len(prefix):].encode("utf-8")):
                child_kind, child_data, child_mode = tree[name]
                parts.extend([
                    token("entry"), token("("), token("name"),
                    nar_string(name[len(prefix):].encode("utf-8")), token("node"),
                    node(name, child_kind, child_data, child_mode), token(")"),
                ])
        elif kind == "link":
            parts.extend([token("symlink"), token("target"), nar_string(data)])
        else:
            parts.append(token("regular"))
            if mode & 0o100:
                parts.extend([token("executable"), token("")])
            parts.extend([token("contents"), nar_string(data)])
        return b"".join(parts) + token(")")

    return token("nix-archive-1") + node("", "dir", b"", 0o755)


def git_digest(entries, algorithm, swh=False):
    tree = tree_with_parents(entries)

    def object_id(kind, data):
        header = kind.encode("ascii") + b" " + str(len(data)).encode("ascii") + b"\0"
        return digest(algorithm, header + data)

    def directory(path):
        prefix = path + "/" if path else ""
        children = []
        for full, (kind, data, mode) in tree.items():
            if not full.startswith(prefix) or "/" in full[len(prefix):]:
                continue
            name = full[len(prefix):].encode("utf-8")
            if kind == "dir":
                child, present = directory(full)
                if not present and not swh:
                    continue
                rights, key = b"40000", name + b"/"
            else:
                child = object_id("blob", data)
                rights = b"120000" if kind == "link" else (
                    b"100755" if mode & (0o111 if swh else 0o100) else b"100644"
                )
                key = name
            children.append((key, rights + b" " + name + b"\0" + child))
        serial = b"".join(value for _, value in sorted(children))
        return object_id("tree", serial), bool(children)

    return directory("")[0]


def expected(entries, scheme, algorithm, original_entries=None):
    if scheme in ("h1", "h1-go"):
        source = original_entries if scheme == "h1-go" and original_entries is not None else entries
        manifest = b""
        for path in sorted(source, key=lambda name: name.encode("utf-8")):
            kind, data, _ = source[path]
            if kind == "dir" and not (scheme == "h1-go" and original_entries is not None):
                continue
            manifest += digest(algorithm, data).hex().encode("ascii") + b"  "
            manifest += path.encode("utf-8") + b"\n"
        raw = digest(algorithm, manifest)
    elif scheme in ("gittree", "swhid"):
        raw = git_digest(entries, algorithm, swh=scheme == "swhid")
    else:
        raw = digest(algorithm, nar_bytes(entries))
    if scheme in ("h1", "h1-go") and algorithm == "sha256":
        return "h1:" + base64.b64encode(raw).decode("ascii")
    if scheme == "gittree" and algorithm in ("sha1", "sha256"):
        return raw.hex()
    if scheme == "swhid" and algorithm == "sha1":
        return "swh:1:dir:" + raw.hex()
    if scheme == "nar" and algorithm == "sha256":
        return "sha256-" + base64.b64encode(raw).decode("ascii")
    return f"dirhash:1:{scheme}:{algorithm}:{raw.hex()}"


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=compression) as archive:
        for name, (kind, data, mode) in entries.items():
            info = zipfile.ZipInfo(name if kind != "dir" or name.endswith("/") else name + "/")
            info.create_system = 3
            info.compress_type = compression
            file_type = stat.S_IFDIR if kind == "dir" else stat.S_IFLNK if kind == "link" else stat.S_IFREG
            info.external_attr = (file_type | mode) << 16
            if kind == "dir":
                info.external_attr |= 0x10
            archive.writestr(info, data)
    return target.getvalue()


def tar_bytes(entries):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, (kind, data, mode) in entries.items():
            info = tarfile.TarInfo(name)
            info.mode = mode
            if kind == "dir":
                info.type = tarfile.DIRTYPE
            elif kind in ("link", "hard"):
                info.type = tarfile.SYMTYPE if kind == "link" else tarfile.LNKTYPE
                info.linkname = data.decode("utf-8")
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
            else:
                info.size = len(data)
            archive.addfile(info, io.BytesIO(data) if info.isreg() else None)
    return target.getvalue()


def single_zip(name, data, method, compressed, *, flags=0, extra=b"", descriptor=False,
               zip64=False, attr=None):
    """Encode ZIP framing independently so tests are not limited by zipfile."""
    crc = zlib.crc32(data)
    if descriptor:
        flags |= 8
    local_extra = extra
    central_extra = extra
    if zip64:
        local_extra += struct.pack("<HHQQ", 1, 16, len(data), len(compressed))
        central_extra += struct.pack("<HHQQQ", 1, 24, len(data), len(compressed), 0)
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 63, flags, method, 0, 0,
        0 if descriptor else crc,
        0 if descriptor else 0xFFFFFFFF if zip64 else len(compressed),
        0 if descriptor else 0xFFFFFFFF if zip64 else len(data),
        len(name), len(local_extra),
    )
    local += name + local_extra + compressed
    if descriptor:
        local += struct.pack("<IIII", 0x08074B50, crc, len(compressed), len(data))
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 63, 63, flags, method,
        0, 0, crc, 0xFFFFFFFF if zip64 else len(compressed), 0xFFFFFFFF if zip64 else len(data),
        len(name), len(central_extra), 0, 0, 0,
        attr if attr is not None else (stat.S_IFREG | 0o644) << 16,
        0xFFFFFFFF if zip64 else 0,
    ) + name + central_extra
    if zip64:
        end = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 63, 63, 0, 0, 1, 1,
                          len(central), len(local))
        end += struct.pack("<IIQI", 0x07064B50, 0, len(local) + len(central), 1)
        end += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0)
    else:
        end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def sparse_tar(version):
    """Small GNU sparse fixture with two data extents and holes at both ends."""
    physical = b"ABCXY"
    logical = b"\0\0ABC" + bytes(5) + b"XY" + bytes(4)
    extents = [(2, 3), (10, 2)]
    info = tarfile.TarInfo("sparse")
    info.mode = 0o644
    info.size = len(physical)
    if version == "gnu":
        info.type = tarfile.GNUTYPE_SPARSE
        header = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
        for index, (offset, size) in enumerate(extents):
            start = 386 + index * 24
            header[start:start + 12] = f"{offset:011o}\0".encode("ascii")
            header[start + 12:start + 24] = f"{size:011o}\0".encode("ascii")
        header[483:495] = f"{len(logical):011o}\0".encode("ascii")
        header[148:156] = b" " * 8
        header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
        result = bytes(header) + physical + bytes((-len(physical)) % 512)
    else:
        fields = [
            ("GNU.sparse.size", str(len(logical))),
            ("GNU.sparse.numblocks", str(len(extents))),
        ]
        payload = physical
        if version == "0.0":
            for offset, size in extents:
                fields.extend([("GNU.sparse.offset", str(offset)), ("GNU.sparse.numbytes", str(size))])
        elif version == "0.1":
            fields.extend([("GNU.sparse.name", "sparse"), ("GNU.sparse.map", "2,3,10,2")])
        else:
            fields = [
                ("GNU.sparse.major", "1"), ("GNU.sparse.minor", "0"),
                ("GNU.sparse.name", "sparse"), ("GNU.sparse.realsize", str(len(logical))),
            ]
            sparse_map = b"2\n2\n3\n10\n2\n"
            payload = sparse_map + bytes((-len(sparse_map)) % 512) + physical
            info.size = len(payload)
        pax = b""
        for key, value in fields:
            line = (key + "=" + value + "\n").encode("utf-8")
            count = len(line) + 2
            while len(str(count)) + 1 + len(line) != count:
                count = len(str(count)) + 1 + len(line)
            pax += str(count).encode("ascii") + b" " + line
        extended = tarfile.TarInfo("PaxHeaders/sparse")
        extended.type = tarfile.XHDTYPE
        extended.size = len(pax)
        result = extended.tobuf() + pax + bytes((-len(pax)) % 512)
        result += info.tobuf() + payload + bytes((-len(payload)) % 512)
    return result + bytes(1024), logical


class Conformance(unittest.TestCase):
    backends = {}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dirhash-conformance-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def write(self, name, data):
        path = self.path / name
        path.write_bytes(data)
        return str(path)

    def commands(self):
        return self.backends.items()

    def execute(self, command, args, cwd=None, env=None):
        return subprocess.run(command + [str(arg) for arg in args],
                              capture_output=True, timeout=90, cwd=cwd, env=env)

    def records(self, command, args, jsonl=False):
        result = self.execute(command, args)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(b"\r", result.stdout)
        self.assertTrue(result.stdout.endswith(b"\n"))
        if jsonl:
            records = [json.loads(line) for line in result.stdout.splitlines()]
        else:
            document = json.loads(result.stdout)
            self.assertEqual(list(document), ["schemaVersion", "results"])
            self.assertEqual(document["schemaVersion"], 1)
            records = document["results"]
        for record in records:
            self.assertEqual(list(record), [
                "path", "source", "archiveEntries", "inputType",
                "scheme", "digestAlgorithm", "value",
            ])
        return records

    def reject(self, command, args, code=None, category=None):
        result = self.execute(command, args)
        self.assertNotEqual(result.returncode, 0)
        if code is not None:
            self.assertEqual(result.returncode, code, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(result.stdout, b"", "A failed invocation published result bytes")
        self.assertTrue(result.stderr)
        if category:
            self.assertTrue(result.stderr.startswith(category.encode("ascii")), result.stderr)
        return result

    def check_values(self, records, entries, originals=None):
        for record in records:
            self.assertEqual(
                record["value"],
                expected(entries, record["scheme"], record["digestAlgorithm"], originals),
                f"{record['scheme']}:{record['digestAlgorithm']}",
            )

    def test_official_go_module_vector(self):
        source = FIXTURES / "quote-v1.5.2.zip"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         "643fcf8ef4e4cbb8f910622c42df3f9a81f3efe8b158a05825a81622c121ca0a")
        with zipfile.ZipFile(source) as archive:
            entries = {item.filename: ("file", archive.read(item), 0o644)
                       for item in archive.infolist()}
        # sum.golang.org/lookup/rsc.io/quote@v1.5.2; keep the module@version prefix.
        published = "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y="
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, COMMON_FLAGS + ["--h1-go", "--format=json", source])
                self.assertEqual(len(records), 6)
                self.check_values(records, entries, entries)
                self.assertEqual(records[0]["value"], published)
                self.assertEqual(records[1]["value"], published)

    def test_official_go_mod_vector(self):
        with zipfile.ZipFile(FIXTURES / "quote-v1.5.2.zip") as archive:
            payload = archive.read("rsc.io/quote@v1.5.2/go.mod")
        entries = {"go.mod": ("file", payload, 0o644)}
        directory = self.path / "module"
        directory.mkdir()
        (directory / "go.mod").write_bytes(payload)
        archive_path = self.write("module.zip", zip_bytes(entries))
        published = "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0="
        for backend, command in self.commands():
            for source in (directory, archive_path):
                with self.subTest(backend=backend, source=str(source)):
                    records = self.records(command, ["--h1", "--h1-go", "--format=json", source])
                    self.assertEqual(len(records), 2)
                    self.assertEqual([record["scheme"] for record in records], ["h1", "h1-go"])
                    for record in records:
                        self.assertEqual(record["value"], published)

    def test_official_swh_archive_vectors(self):
        source = FIXTURES / "swh-sample-folder.tgz"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         "307ebda0071ca5975f618e192c8417161e19b6c8bf581a26061b76dc8e85321d")
        # Published in swh-model's SAMPLE_FOLDER_SWHIDS.
        published = {
            "bar": "swh:1:dir:3c1f578394f4623f74a0ba7fe761729f59fc6ec4",
            "bar/barfoo": "swh:1:dir:c3020f6bf135a38c6df3afeb5fb38232c5e07087",
        }
        with tarfile.open(source) as archive:
            entries = {}
            for member in archive.getmembers():
                name = member.name.partition("/")[2]
                if not name:
                    continue
                if member.isdir():
                    entry = ("dir", b"", member.mode)
                elif member.issym():
                    entry = ("link", member.linkname.encode("utf-8"), member.mode)
                else:
                    self.assertTrue(member.isfile())
                    entry = ("file", archive.extractfile(member).read(), member.mode)
                entries[name] = entry
            for backend, command in self.commands():
                with self.subTest(backend=backend, archive=True):
                    records = self.records(command, COMMON_FLAGS + [
                        "--strip-components=1", "--format=json", source,
                    ])
                    self.assertEqual(len(records), 5)
                    self.check_values(records, entries)
                    self.assertEqual(records[3]["value"],
                                     "swh:1:dir:e8b0f1466af8608c8a3fb9879db172b887e80759")
            for index, (subdir, value) in enumerate(published.items()):
                folder = self.path / str(index)
                folder.mkdir()
                prefix = "sample-folder/" + subdir + "/"
                for member in archive.getmembers():
                    if not member.name.startswith(prefix):
                        continue
                    name = member.name[len(prefix):]
                    self.assertNotIn("..", name.split("/"))
                    self.assertFalse(name.startswith(("/", "\\")))
                    target = folder / name
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        self.assertTrue(member.isfile())
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(archive.extractfile(member).read())
                        target.chmod(member.mode)
                for backend, command in self.commands():
                    with self.subTest(backend=backend, subtree=subdir):
                        records = self.records(command, ["--swhid", "--format=json", folder])
                        self.assertEqual(len(records), 1)
                        self.assertEqual(records[0]["value"], value)

    def test_published_nix_nar_and_git_tree_vectors(self):
        source = FIXTURES / "nix-systems-default-d36eeed.tar.gz"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         "20fbc8f944dff0e70675b7ef11ccf90a9c88dfad38789dfc6486ec772660069f")
        # NixOS/nixos-homepage's flake.lock pins the recursive NAR hash;
        # the source commit's tree ID independently supplies the Git vector.
        published = {
            "nar": "sha256-uuanbkFk8a313Zfrxdcz8Us/yQtaxNnKJtX8v0ZPpd8=",
            "gittree": "534351a8910b267d46775dcd0bf1678a52505a39",
        }
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, [
                    "--gittree", "--nar", "--strict", "--strip-components=1",
                    "--format=json", source,
                ])
                self.assertEqual(len(records), 2)
                for record in records:
                    self.assertEqual(record["value"], published[record["scheme"]])

    def test_recursive_wrapped_official_archive_vectors(self):
        """Recurse into three official-vector module ZIPs wrapped in one ZIP.

        The temporary outer wrapper places each unchanged fixture at a
        second-level prefix (a/, b/, c/). The parent hashes the nested
        archives' raw bytes. Every nested root keeps its original
        module@version prefix, so each published sum.golang.org module h1
        applies directly to the raw nested result without stripping or any
        wrapper adjustment; --strip-components would apply only to the outer
        input, never to a nested archive. None of these module ZIPs contains
        explicit directory markers, so --h1 and --h1-go both reproduce the
        official checksum. Standalone runs of the same fixtures additionally
        prove recursion/direct equivalence transitively.

        All hash selections run recursively: implementations stage nested
        archives into private temporary files, so even deferred-size
        (data-descriptor) module ZIPs support every construction including
        Git/SWH blob headers. The recursive run is repeated under --strict
        with identical expected records.
        """
        fixtures = [
            ("a/quote-v1.5.2.zip", FIXTURES / "quote-v1.5.2.zip",
             "643fcf8ef4e4cbb8f910622c42df3f9a81f3efe8b158a05825a81622c121ca0a",
             "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y="),
            ("b/uuid-v1.6.0.zip", FIXTURES / "uuid-v1.6.0.zip",
             "d0f02f377217f42702e259684e06441edbf5140dddcc34ba9bea56038b38a6ed",
             "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0="),
            ("c/errors-v0.9.1.zip", FIXTURES / "errors-v0.9.1.zip",
             "d4c36b8bcd0616290a3913215e0f53b931bd6e00670596f2960df1b44af2bd07",
             "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4="),
        ]
        inner = {}
        payloads = {}
        for name, path, pin, published in fixtures:
            payloads[name] = path.read_bytes()
            self.assertEqual(hashlib.sha256(payloads[name]).hexdigest(), pin)
            with zipfile.ZipFile(path) as archive:
                entries = {item.filename: ("file", archive.read(item), 0o644)
                           for item in archive.infolist()}
            # No explicit directory markers: the published h1 binds both the
            # common and the Go-compatible manifest views of the raw archive.
            self.assertFalse(any(item.endswith("/") for item in entries))
            self.assertEqual(expected(entries, "h1", "sha256"), published)
            inner[name] = entries

        # Controlled outer metadata: fixed timestamps, regular 0644 entries,
        # no explicit directory markers, so the parent expectation is fully
        # determined by the nested archives' raw bytes.
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w") as archive:
            for name, _, _, _ in fixtures:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, payloads[name])
        outer_entries = {name: ("file", payloads[name], 0o644)
                         for name, _, _, _ in fixtures}
        outer = self.write("vectors.zip", target.getvalue())

        flags = COMMON_FLAGS + ["--h1-go"]
        selections = [("h1", "sha256"), ("h1-go", "sha256"), ("gittree", "sha1"),
                      ("gittree", "sha256"), ("swhid", "sha1"), ("nar", "sha256")]
        for backend, command in self.commands():
            groups = None
            with self.subTest(backend=backend, phase="recurse"):
                records = self.records(command, flags + [
                    "--recurse", "--format=json", outer,
                ])
                self.assertEqual(len(records), 4 * len(selections))
                groups = [records[index:index + len(selections)]
                          for index in range(0, len(records), len(selections))]
                for group in groups:
                    self.assertEqual(
                        [(r["scheme"], r["digestAlgorithm"]) for r in group],
                        selections)
                for record in groups[0]:
                    self.assertEqual(record["path"], outer)
                    self.assertEqual(record["source"], outer)
                    self.assertEqual(record["archiveEntries"], [])
                    self.assertEqual(record["inputType"], "zip")
                self.check_values(groups[0], outer_entries, outer_entries)
                for group, (name, _, _, published) in zip(groups[1:], fixtures):
                    for record in group:
                        self.assertEqual(record["archiveEntries"], [name])
                        self.assertEqual(record["path"], outer + "!/" + name)
                        self.assertEqual(record["source"], outer)
                        self.assertEqual(record["inputType"], "zip")
                    self.check_values(group, inner[name], inner[name])
                    for scheme in ("h1", "h1-go"):
                        record = next(r for r in group if r["scheme"] == scheme)
                        self.assertEqual(record["value"], published)
            if groups is None:
                continue  # The recursion failure was already recorded above.
            with self.subTest(backend=backend, phase="recurse-strict"):
                # Strict validation must not change any published value.
                strict_records = self.records(command, flags + [
                    "--strict", "--recurse", "--format=json", outer,
                ])
                self.assertEqual(strict_records, records)
            for group, (name, path, _, published) in zip(groups[1:], fixtures):
                with self.subTest(backend=backend, phase="standalone", archive=name):
                    # Recursion must equal hashing the inner archive directly.
                    standalone = self.records(command, flags + ["--format=json", path])
                    self.assertEqual(len(standalone), len(selections))
                    self.check_values(standalone, inner[name], inner[name])
                    by_scheme = {r["scheme"]: r["value"] for r in standalone}
                    self.assertEqual(by_scheme["h1"], published)
                    self.assertEqual(by_scheme["h1-go"], published)
                    self.assertEqual(
                        [(r["scheme"], r["digestAlgorithm"], r["inputType"], r["value"])
                         for r in group],
                        [(r["scheme"], r["digestAlgorithm"], r["inputType"], r["value"])
                         for r in standalone])

    def test_seeded_tree_and_archive_equivalence(self):
        rng = random.Random(0xD1A5)
        for index in range(8):
            entries = {"empty/nested": ("dir", b"", 0o755)}
            for item in range(12):
                name = rng.choice(("a", "a.b", "z", "\u00e9", "\U0001f600"))
                name += "/" + str(item) if item % 2 else str(item)
                data = rng.randbytes(rng.randrange(0, 2048))
                entries[name] = ("file", data, rng.choice((0o644, 0o755, 0o654)))
            # Reverse archive order to stress inferred parents and sorted finalization.
            entries = dict(reversed(list(entries.items())))
            for suffix, payload in (("zip", zip_bytes(entries)), ("tar", tar_bytes(entries))):
                source = self.write(f"seeded-{index}.{suffix}", payload)
                for backend, command in self.commands():
                    with self.subTest(backend=backend, case=index, format=suffix):
                        records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", source])
                        self.assertEqual(len(records), len(COMMON_FLAGS))
                        self.check_values(records, entries)

    def test_discovery_content_suffix_and_depth_limits(self):
        inner = zip_bytes({"a": ("file", b"x", 0o644)})
        candidates = [
            ("payload.bin", inner, True),
            ("library.JAR", inner, True),
            ("wrong.tar", inner, False),
            ("broken.jar", b"not an archive", False),
        ]
        for index, (name, data, valid) in enumerate(candidates):
            source = self.write(f"discovery-{index}.zip", zip_bytes({name: ("file", data, 0o644)}))
            for backend, command in self.commands():
                with self.subTest(backend=backend, candidate=name):
                    opaque = self.records(command, ["--h1", "--format=json", source])
                    if valid:
                        records = self.records(command, ["--h1", "--recurse", "--format=json", source])
                        self.assertEqual(len(records), 2)
                        self.assertEqual(records[0], opaque[0])
                        self.assertEqual(records[1]["archiveEntries"], [name])
                        self.reject(command, ["--h1", "--recurse", "--max-depth=0", source],
                                    1, "LIMIT_EXCEEDED")
                    else:
                        self.reject(command, ["--h1", "--recurse", source], 1)
                        self.reject(command, ["--h1", "--strict", source], 1)

    def test_strict_symlink_chains_and_stripped_targets(self):
        fixtures = [
            {"a": ("link", b"b", 0o777), "b": ("link", b"a", 0o777)},
            {"dir/up": ("link", b"..", 0o777),
             "escape": ("link", b"dir/up/../outside", 0o777)},
        ]
        for index, entries in enumerate(fixtures):
            source = self.write(f"chain-{index}.zip", zip_bytes(entries))
            for backend, command in self.commands():
                with self.subTest(backend=backend, fixture=index):
                    self.reject(command, ["--h1", "--strict", "--exclude=**", source], 1)
        source = self.write("projected-links.zip", zip_bytes({
            "pkg/link": ("link", b"../other/target", 0o777),
            "other/target": ("file", b"x", 0o644),
        }))
        for backend, command in self.commands():
            with self.subTest(backend=backend, projection=True):
                self.records(command, ["--h1", "--strict", "--format=json", source])
                self.reject(command, ["--h1", "--strict", "--strip-components=1", source], 1)

    def test_unicode_path_extra_resolution_and_validation(self):
        raw_name = b"cafe"
        logical_name = "caf\u00e9"
        data = b"unicode path"
        value = b"\x01" + struct.pack("<I", zlib.crc32(raw_name)) + logical_name.encode("utf-8")
        extra = struct.pack("<HH", 0x7075, len(value)) + value
        source = self.write("unicode-extra.zip", single_zip(raw_name, data, 0, data, extra=extra))
        manifest = hashlib.sha256(data).hexdigest().encode() + b"  " + raw_name + b"\n"
        raw_h1 = "h1:" + base64.b64encode(hashlib.sha256(manifest).digest()).decode()
        bad_value = b"\x01" + struct.pack("<I", zlib.crc32(raw_name) ^ 1) + b"other"
        bad_extra = struct.pack("<HH", 0x7075, len(bad_value)) + bad_value
        bad = self.write("invalid-extra.zip", single_zip(raw_name, data, 0, data, extra=bad_extra))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, ["--h1", "--h1-go", "--strict", "--format=json", source])
                self.check_values(records[:1], {logical_name: ("file", data, 0o644)})
                self.assertEqual(records[1]["value"], raw_h1)
                self.reject(command, ["--h1", bad], 1)

    def test_control_records_zero_limits_and_excluded_validation(self):
        pax = self.write("pax.tar", tar_bytes({"a" * 120: ("file", b"x", 0o644)}))
        invalid = self.write("excluded-invalid.zip", single_zip(b"../bad", b"x", 0, b"x"))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                self.reject(command, ["--h1", "--max-entries=1", pax], 1, "LIMIT_EXCEEDED")
                self.reject(command, ["--h1", "--max-entries=0", pax], 1, "LIMIT_EXCEEDED")
                self.reject(command, ["--h1", "--max-expanded-bytes=0", pax], 1, "LIMIT_EXCEEDED")
                self.reject(command, ["--h1", "--exclude=**", invalid], 1)
                self.reject(command, ["--h1", "--strip-components=100", "--exclude=**", pax], 1)

    def test_tar_hardlink_chains_excluded_targets_and_cycles(self):
        entries = {
            "first": ("hard", b"second", 0o755),
            "second": ("hard", b"target", 0o644),
            "target": ("file", b"resolved", 0o644),
        }
        source = self.write("hard-chains.tar", tar_bytes(entries))
        invalid = [
            {"first": ("hard", b"missing", 0o644)},
            {"first": ("hard", b"second", 0o644), "second": ("hard", b"first", 0o644)},
            {"first": ("hard", b"link", 0o644), "link": ("link", b"target", 0o777),
             "target": ("file", b"x", 0o644)},
        ]
        bad = [self.write(f"hard-invalid-{index}.tar", tar_bytes(value))
               for index, value in enumerate(invalid)]
        logical = {"first": ("file", b"resolved", 0o755)}
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, COMMON_FLAGS + [
                    "--exclude=target", "--exclude=second", "--strict", "--format=json", source,
                ])
                self.check_values(records, logical)
                for broken in bad:
                    self.reject(command, ["--h1", "--exclude=**", broken], 1)

    def test_explicit_root_markers_and_inferred_parent_records(self):
        entries = {
            "lib/a": ("file", b"x", 0o644),
            "lib": ("dir", b"", 0o755),
            "./": ("dir", b"", 0o755),
        }
        logical = {"lib": entries["lib"], "lib/a": entries["lib/a"]}
        source = self.write("parents.zip", zip_bytes(entries))
        bad = self.write("root-file.zip", single_zip(b".", b"x", 0, b"x"))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", source])
                self.check_values(records, logical)
                self.reject(command, ["--h1", bad], 1)
                self.reject(command, ["--h1", "--strip-components=0", self.path], 2)

    def test_recursive_order_boundaries_and_nar_accounting(self):
        leaf_entries = {"x": ("file", b"x", 0o644)}
        leaf = zip_bytes(leaf_entries)
        middle_entries = {"deep.zip": ("file", leaf, 0o644)}
        middle = zip_bytes(middle_entries)
        outer_entries = {
            "z.zip": ("file", leaf, 0o644),
            "a.zip": ("file", middle, 0o644),
        }
        source = self.write("order.zip", zip_bytes(outer_entries))
        # Each occurrence is charged once, despite NAR's additional passes.
        expanded = len(leaf) * 2 + len(middle) + 2
        expected_paths = [[], ["a.zip"], ["a.zip", "deep.zip"], ["z.zip"]]
        expected_entries = [outer_entries, middle_entries, leaf_entries, leaf_entries]
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, [
                    "--nar", "--recurse", f"--max-expanded-bytes={expanded}",
                    "--format=json", source,
                ])
                self.assertEqual([r["archiveEntries"] for r in records], expected_paths)
                for record, entries in zip(records, expected_entries):
                    self.check_values([record], entries)
                self.reject(command, [
                    "--nar", "--recurse", f"--max-expanded-bytes={expanded - 1}", source,
                ], 1, "LIMIT_EXCEEDED")

    def test_gzip_optional_header_fields_and_header_crc(self):
        entries = {"a": ("file", b"x", 0o644)}
        basic = gzip.compress(tar_bytes(entries), mtime=0)
        header = bytearray(basic[:10])
        header[3] = 2 | 4 | 8 | 16
        extra = b"xy" + struct.pack("<H", 3) + b"abc"
        header += struct.pack("<H", len(extra)) + extra + b"source.tar\0" + b"a comment\0"
        header += struct.pack("<H", zlib.crc32(header) & 0xFFFF)
        good = self.write("gzip-fields.tgz", bytes(header) + basic[10:])
        header[-1] ^= 1
        bad = self.write("gzip-header-crc.tgz", bytes(header) + basic[10:])
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", good])
                self.check_values(records, entries)
                self.reject(command, ["--h1", bad], 1)

    def test_directory_and_archive_hash_oracles(self):
        entries = {
            "alpha": ("file", b"hello\n", 0o644),
            "folder/value": ("file", bytes(range(256)), 0o644),
            "empty": ("dir", b"", 0o755),
            "\ue000": ("file", b"unicode-1", 0o644),
            "\U0001f600": ("file", b"unicode-2", 0o644),
        }
        folder = self.path / "directory"
        folder.mkdir()
        for path, (kind, data, _) in entries.items():
            target = folder / path
            if kind == "dir":
                target.mkdir(parents=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        sources = {
            str(folder): "directory",
            self.write("a.zip", zip_bytes(entries)): "zip",
            self.write("a.tar", tar_bytes(entries)): "tar",
            self.write("a.tar.gz", gzip.compress(tar_bytes(entries), mtime=0)): "tar.gz",
        }
        for backend, command in self.commands():
            for source, kind in sources.items():
                with self.subTest(backend=backend, source=kind):
                    records = self.records(command, COMMON_FLAGS + ["--format=json", source])
                    self.assertEqual(len(records), 5)
                    self.check_values(records, entries)
                    for record in records:
                        self.assertEqual(record["source"], source)
                        self.assertEqual(record["path"], source)
                        self.assertEqual(record["archiveEntries"], [])
                        self.assertEqual(record["inputType"], kind)

    def test_all_digest_overrides(self):
        entries = {"a": ("file", b"payload", 0o755)}
        source = self.write("digests.zip", zip_bytes(entries))
        flags = [f"--{scheme}:{algorithm}" for scheme in SCHEMES
                 for algorithm in DIGESTS if algorithm != "blake3"]
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, flags[::-1] + ["--format=json", source])
                self.assertEqual(len(records), len(flags))
                self.check_values(records, entries)
                self.assertEqual(
                    [(r["scheme"], r["digestAlgorithm"]) for r in records],
                    [(s, a) for s in SCHEMES for a in DIGESTS if a != "blake3"],
                )

    def test_blake3_known_empty_manifest_and_parity(self):
        folder = self.path / "empty"
        folder.mkdir()
        values = []
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, [
                    "--h1:blake3", "--h1-go:blake3", "--gittree:blake3",
                    "--swhid:blake3", "--nar:blake3", "--format=json", folder,
                ])
                empty_digest = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
                self.assertEqual(records[0]["value"], "dirhash:1:h1:blake3:" + empty_digest)
                self.assertEqual(records[1]["value"], "dirhash:1:h1-go:blake3:" + empty_digest)
                values.append(records)
        for other in values[1:]:
            self.assertEqual(values[0], other)

    def test_directory_markers_and_go_compatibility(self):
        file_entry = {"lib/a": ("file", b"A", 0o644)}
        marked = {"lib/": ("dir", b"", 0o755), **file_entry}
        sources = [
            (self.write("plain.zip", zip_bytes(file_entry)), file_entry),
            (self.write("marked.zip", zip_bytes(marked)), marked),
        ]
        for backend, command in self.commands():
            for source, original in sources:
                with self.subTest(backend=backend, source=source):
                    records = self.records(command, COMMON_FLAGS + ["--h1-go", "--format=json", source])
                    self.check_values(records, file_entry, original)

    def test_swh_preserves_empty_subdirectories_for_all_digests(self):
        entries = {"parent/empty": ("dir", b"", 0o755)}
        source = self.write("empty-subtree.zip", zip_bytes(entries))
        empty = self.write("empty-root.zip", zip_bytes({}))
        flags = [f"--{scheme}:{algorithm}" for scheme in ("gittree", "swhid")
                 for algorithm in DIGESTS]
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, flags + ["--format=json", source])
                root = self.records(command, flags + ["--format=json", empty])
                self.assertEqual(len(records), len(flags))
                self.check_values([r for r in records if r["digestAlgorithm"] != "blake3"], entries)
                for record, root_record in zip(records, root):
                    if record["scheme"] == "gittree":
                        self.assertEqual(record["value"], root_record["value"])
                    else:
                        self.assertNotEqual(record["value"], root_record["value"])

    def test_native_executable_rules_and_symlinks(self):
        entries = {
            "owner": ("file", b"same", 0o744),
            "group": ("file", b"same", 0o654),
            "other": ("file", b"same", 0o645),
            "plain": ("file", b"same", 0o644),
            "link": ("link", b"plain", 0o777),
        }
        source = self.write("modes.zip", zip_bytes(entries))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", source])
                self.check_values(records, entries)
                self.assertNotEqual(records[1]["value"], records[3]["value"].removeprefix("swh:1:dir:"))

    def test_tar_forward_hardlink(self):
        originals = {
            "copy": ("hard", b"target", 0o755),
            "target": ("file", b"real contents", 0o644),
        }
        logical = {
            "copy": ("file", b"real contents", 0o755),
            "target": originals["target"],
        }
        source = self.write("links.tar", tar_bytes(originals))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, COMMON_FLAGS + ["--format=json", source])
                self.check_values(records, logical)

    def test_sparse_tar_variants(self):
        for version in ("gnu", "0.0", "0.1", "1.0"):
            archive, logical = sparse_tar(version)
            # First ensure that the independent fixture is an actual readable TAR.
            with tarfile.open(fileobj=io.BytesIO(archive)) as reference:
                self.assertEqual(reference.extractfile("sparse").read(), logical)
            source = self.write(f"sparse-{version}.tar", archive)
            for backend, command in self.commands():
                with self.subTest(backend=backend, version=version):
                    records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", source])
                    self.check_values(records, {"sparse": ("file", logical, 0o644)})

    def test_bzip2_and_xz_zip_codecs(self):
        data = b"Codec integration is not a new compression algorithm.\n" * 100
        bzip = self.write("bzip.zip", zip_bytes({"a": ("file", data, 0o644)}, zipfile.ZIP_BZIP2))
        xz = self.write("xz.zip", single_zip(b"a", data, 95, lzma.compress(data)))
        for backend, command in self.commands():
            for source in (bzip, xz):
                with self.subTest(backend=backend, source=source):
                    records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", source])
                    self.check_values(records, {"a": ("file", data, 0o644)})

    def test_zstandard_zip_methods(self):
        data = b"A raw block inside a valid Zstandard frame."
        # Single-segment frame with one last, uncompressed block.
        frame = b"\x28\xb5\x2f\xfd\x20" + bytes([len(data)])
        frame += ((len(data) << 3) | 1).to_bytes(3, "little") + data
        for method in (20, 93):
            source = self.write(f"zstandard-{method}.zip", single_zip(b"a", data, method, frame))
            for backend, command in self.commands():
                with self.subTest(backend=backend, method=method):
                    records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", source])
                    self.check_values(records, {"a": ("file", data, 0o644)})

    def test_java_deflate64_and_explicit_unsupported_methods(self):
        data = b"Deflate64 accepts ordinary uncompressed DEFLATE blocks."
        block = b"\x01" + struct.pack("<HH", len(data), len(data) ^ 0xFFFF) + data
        source = self.write("deflate64.zip", single_zip(b"a", data, 9, block))
        unsupported = self.write("unsupported.zip", single_zip(b"a", data, 98, block))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                if backend == "java":
                    records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", source])
                    self.check_values(records, {"a": ("file", data, 0o644)})
                else:
                    result = self.execute(command, ["--h1", source])
                    if result.returncode != 0:
                        self.reject(command, ["--h1", source], 3, "UNSUPPORTED_METHOD")
                self.reject(command, ["--h1", unsupported], 3, "UNSUPPORTED_METHOD")

    def test_legacy_zip_names_common_utf8_and_go_raw(self):
        raw_name = b"caf\x82"
        data = b"CP437"
        source = self.write("legacy.zip", single_zip(raw_name, data, 0, data))
        raw_manifest = hashlib.sha256(data).hexdigest().encode() + b"  " + raw_name + b"\n"
        go_value = "h1:" + base64.b64encode(hashlib.sha256(raw_manifest).digest()).decode()
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, ["--h1", "--h1-go", "--strict", "--format=json", source])
                self.check_values(records[:1], {"caf\u00e9": ("file", data, 0o644)})
                self.assertEqual(records[1]["value"], go_value)

    def test_invalid_zip_utf8_never_replaced(self):
        source = self.write("utf8.zip", single_zip(b"bad\xff", b"x", 0, b"x", flags=0x800))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                self.reject(command, ["--gittree", source], 1)

    def test_strict_zip64_and_descriptors(self):
        data = b"ZIP framing with a descriptor or ZIP64"
        for style in ("descriptor", "zip64"):
            archive = single_zip(b"a", data, 0, data, **{style: True})
            with zipfile.ZipFile(io.BytesIO(archive)) as reference:
                self.assertEqual(reference.read("a"), data)
            source = self.write(style + ".zip", archive)
            for backend, command in self.commands():
                with self.subTest(backend=backend, style=style):
                    records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", source])
                    self.check_values(records, {"a": ("file", data, 0o644)})

    def test_strip_counts_dot_and_keeps_original_exclusion_paths(self):
        originals = {"./pkg/": ("dir", b"", 0o755), "./pkg/a": ("file", b"A", 0o644)}
        source = self.write("prefix.zip", zip_bytes(originals))
        cases = [
            (0, {"pkg": ("dir", b"", 0o755), "pkg/a": originals["./pkg/a"]}, originals),
            (1, {"pkg": ("dir", b"", 0o755), "pkg/a": originals["./pkg/a"]},
             {"pkg/": originals["./pkg/"], "pkg/a": originals["./pkg/a"]}),
            (2, {"a": originals["./pkg/a"]}, {"a": originals["./pkg/a"]}),
        ]
        for backend, command in self.commands():
            for depth, logical, compat in cases:
                with self.subTest(backend=backend, depth=depth):
                    records = self.records(command, COMMON_FLAGS + [
                        "--h1-go", f"--strip-components={depth}", "--format=json", source,
                    ])
                    self.check_values(records, logical, compat)
            with self.subTest(backend=backend, exclusion=True):
                records = self.records(command, [
                    "--h1", "--strip-components=2", "--exclude=pkg/a", "--format=json", source,
                ])
                self.check_values(records, {})

    def test_strip_shallow_and_collision_errors(self):
        sources = [
            self.write("shallow.zip", zip_bytes({"README": ("file", b"x", 0o644)})),
            self.write("collision.zip", zip_bytes({
                "a/x": ("file", b"1", 0o644), "b/x": ("file", b"2", 0o644),
            })),
        ]
        for backend, command in self.commands():
            for source in sources:
                with self.subTest(backend=backend, source=source):
                    self.reject(command, ["--h1", "--strip-components=1", source], 1)

    def test_strip_does_not_change_nested_archive_paths(self):
        inner_entries = {"nested/file": ("file", b"X", 0o644)}
        entries = {"pkg/inner.zip": ("file", zip_bytes(inner_entries), 0o644)}
        source = self.write("outer-prefix.zip", zip_bytes(entries))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, [
                    "--h1", "--recurse", "--strip-components=1", "--format=json", source,
                ])
                self.assertEqual(len(records), 2)
                self.assertEqual(records[1]["archiveEntries"], ["pkg/inner.zip"])
                self.check_values(records[:1], {"inner.zip": entries["pkg/inner.zip"]})
                self.check_values(records[1:], inner_entries)

    def test_filesystem_symlinks_and_go_confinement(self):
        folder = self.path / "links"
        folder.mkdir()
        (folder / "target").write_bytes(b"data")
        try:
            (folder / "link").symlink_to("target")
        except OSError as error:
            self.skipTest(f"Host cannot create filesystem symlinks: {error}")
        entries = {
            "target": ("file", b"data", 0o644),
            "link": ("link", b"target", 0o777),
        }
        for backend, command in self.commands():
            with self.subTest(backend=backend, confined=True):
                records = self.records(command, COMMON_FLAGS + ["--strict", "--format=json", folder])
                self.check_values(records, entries)
                records = self.records(command, ["--h1-go", "--format=json", folder])
                self.check_values(records, {
                    "target": entries["target"], "link": ("file", b"data", 0o644),
                })
        (self.path / "outside").write_bytes(b"must not be opened")
        (folder / "escape").symlink_to("../outside")
        entries["escape"] = ("link", b"../outside", 0o777)
        for backend, command in self.commands():
            with self.subTest(backend=backend, confined=False):
                # Strict archive confinement must not accidentally become a filesystem rule.
                records = self.records(command, ["--h1", "--strict", "--format=json", folder])
                self.check_values(records, entries)
                self.reject(command, ["--h1-go", folder], 1)

    def test_recursion_parent_bytes_and_inner_excludes(self):
        nested_entries = {"keep": ("file", b"K", 0o644), ".git/config": ("file", b"G", 0o644)}
        nested = zip_bytes(nested_entries)
        outer_entries = {"lib/inner.zip": ("file", nested, 0o644), "z": ("file", b"Z", 0o644)}
        source = self.write("outer.zip", zip_bytes(outer_entries))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                # h1 avoids the documented unknown-size Git blob streaming limitation.
                plain = self.records(command, ["--h1", "--format=json", source])
                recursive = self.records(command, [
                    "--h1", "--recurse", "--exclude=lib/inner.zip!/.git/",
                    "--format=json", source,
                ])
                self.assertEqual(recursive[0], plain[0])
                self.assertEqual(len(recursive), 2)
                self.assertEqual(recursive[1]["archiveEntries"], ["lib/inner.zip"])
                self.assertEqual(recursive[1]["path"], source + "!/lib/inner.zip")
                self.check_values(recursive[1:], {"keep": nested_entries["keep"]})

    def test_recursive_strict_and_excluded_nested_archive(self):
        bad = zip_bytes({"../unsafe": ("file", b"X", 0o644)})
        entries = {"bad.zip": ("file", bad, 0o644)}
        source = self.write("container.zip", zip_bytes(entries))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                self.reject(command, ["--h1", "--strict", source], 1)
                records = self.records(command, [
                    "--h1", "--strict", "--exclude=bad.zip", "--format=json", source,
                ])
                self.check_values(records, {})

    def test_integrity_and_strict_layout_errors_are_atomic(self):
        good = zip_bytes({"a": ("file", b"abc", 0o644)})
        mismatch = bytearray(good)
        mismatch[30] = ord("b")
        corrupted = bytearray(zip_bytes({"a": ("file", b"abc", 0o644)}, zipfile.ZIP_STORED))
        corrupted[31] ^= 1
        sources = [
            (self.write("trailing.zip", good + b"junk"), True),
            (self.write("mismatch.zip", mismatch), True),
            (self.write("corrupt.zip", corrupted), False),
            (self.write("trailing.tar", tar_bytes({"a": ("file", b"a", 0o644)}) + b"junk"), True),
            (self.write("members.tgz", gzip.compress(tar_bytes({})) + gzip.compress(b"extra")), True),
        ]
        for backend, command in self.commands():
            for source, strict in sources:
                with self.subTest(backend=backend, source=source):
                    self.reject(command, ["--h1"] + (["--strict"] if strict else []) + [source], 1)

    def test_compressed_zip_stream_must_consume_its_extent(self):
        data = b"compressed payload"
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(data) + compressor.flush()
        for suffix in (b"junk", compressed):
            source = self.write("compressed-extra.zip",
                                single_zip(b"a", data, 8, compressed + suffix))
            for backend, command in self.commands():
                for strict in (False, True):
                    with self.subTest(backend=backend, strict=strict, suffix=suffix.hex()):
                        self.reject(command, ["--h1"] + (["--strict"] if strict else []) + [source], 1)

    def test_baseline_and_strict_name_rejections(self):
        names = ("../x", "/absolute", "a\\b", "a/./b", "a//b", "C:x")
        strict_names = ("NUL.txt", "a.", "a ", "a\u200db", "a\u0001b", "a\ufdd0b")
        fixtures = [(name, False) for name in names] + [(name, True) for name in strict_names]
        fixtures += [("newline\nx", False)]
        for index, (name, strict) in enumerate(fixtures):
            source = self.write(f"bad-{index}.zip", single_zip(
                name.encode("utf-8"), b"x", 0, b"x", flags=0x800,
            ))
            for backend, command in self.commands():
                with self.subTest(backend=backend, name=repr(name)):
                    self.reject(command, ["--h1"] + (["--strict"] if strict else []) + [source], 1)

    def test_duplicate_casefold_and_normalization_collisions(self):
        duplicate = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("a", b"first")
                archive.writestr("a", b"second")
        fixtures = [
            (duplicate.getvalue(), False),
            (zip_bytes({"A": ("file", b"x", 0o644), "a": ("file", b"x", 0o644)}), True),
            (zip_bytes({"\u00e9": ("file", b"x", 0o644), "e\u0301": ("file", b"x", 0o644)}), True),
            (zip_bytes({"Stra\u00dfe": ("file", b"x", 0o644), "STRASSE": ("file", b"x", 0o644)}), True),
            (zip_bytes({"\u03c2": ("file", b"x", 0o644), "\u03c3": ("file", b"x", 0o644)}), True),
        ]
        for index, (data, strict) in enumerate(fixtures):
            source = self.write(f"collision-{index}.zip", data)
            for backend, command in self.commands():
                with self.subTest(backend=backend, fixture=index):
                    self.reject(command, ["--h1"] + (["--strict"] if strict else []) + [source], 1)

    def test_strict_archive_symlink_resolution(self):
        targets = ("../outside", "/absolute", "missing", "self", "C:\\x")
        for index, target in enumerate(targets):
            source = self.write(f"link-{index}.zip", zip_bytes({
                "self": ("link", target.encode(), 0o777),
            }))
            for backend, command in self.commands():
                with self.subTest(backend=backend, target=target):
                    self.reject(command, ["--h1", "--strict", source], 1)
        source = self.write("excluded-target.zip", zip_bytes({
            "link": ("link", b"target", 0o777), "target": ("file", b"X", 0o644),
        }))
        for backend, command in self.commands():
            with self.subTest(backend=backend, excluded_target=True):
                records = self.records(command, [
                    "--h1", "--strict", "--exclude=target", "--format=json", source,
                ])
                self.check_values(records, {"link": ("link", b"target", 0o777)})

    def test_limits_and_excluded_special_entries(self):
        source = self.write("limited.zip", zip_bytes({"dir/a": ("file", b"abc", 0o644)}))
        special = self.write("fifo.tar", tar_bytes({"fifo": ("fifo", b"", 0o644)}))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                self.reject(command, ["--h1", "--max-entries=1", source], 1, "LIMIT_EXCEEDED")
                self.reject(command, ["--h1", "--max-expanded-bytes=2", source], 1, "LIMIT_EXCEEDED")
                self.reject(command, ["--h1", "--exclude=fifo", special], 1, "SPECIAL_FILE")
                records = self.records(command, [
                    "--h1", "--max-entries=unlimited", "--max-expanded-bytes=unlimited",
                    "--format=json", source,
                ])
                self.check_values(records, {"dir/a": ("file", b"abc", 0o644)})

    def test_exclusion_globs_and_literal_archive_boundary(self):
        entries = {
            "root.tmp": ("file", b"root", 0o644),
            "sub/deep.tmp": ("file", b"deep", 0o644),
            "sub/keep": ("file", b"keep", 0o644),
        }
        source = self.write("globs.zip", zip_bytes(entries))
        for backend, command in self.commands():
            for pattern, removed in [
                ("*.tmp", {"root.tmp"}), ("**/*.tmp", {"root.tmp", "sub/deep.tmp"}),
                ("sub/", {"sub/deep.tmp", "sub/keep"}),
            ]:
                with self.subTest(backend=backend, pattern=pattern):
                    records = self.records(command, ["--h1", "--exclude=" + pattern, "--format=json", source])
                    self.check_values(records, {key: value for key, value in entries.items() if key not in removed})
        inner = zip_bytes({"x": ("file", b"x", 0o644), "y": ("file", b"y", 0o644)})
        source = self.write("bang.zip", zip_bytes({"a!b.zip": ("file", inner, 0o644)}))
        for backend, command in self.commands():
            with self.subTest(backend=backend, bang=True):
                records = self.records(command, [
                    "--h1", "--recurse", "--exclude=a!!b.zip!/x", "--format=json", source,
                ])
                self.assertEqual(records[1]["path"], source + "!/a!!b.zip")
                self.check_values(records[1:], {"y": ("file", b"y", 0o644)})

    def test_formats_selection_and_usage(self):
        source = self.write("format!.zip", zip_bytes({"a": ("file", b"x", 0o644)}))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                selections = ["--h1", "--h1:sha256", "--h1:sha512", "--h1-go", "--gittree",
                              "--gittree:sha256", "--swhid", "--nar"]
                json_records = self.records(command, selections + ["--format=json", source])
                jsonl_records = self.records(command, selections + ["--format=jsonl", source], jsonl=True)
                self.assertEqual(json_records, jsonl_records)
                self.assertEqual(len(json_records), 7)
                result = self.execute(command, selections + [source])
                expected_text = "".join(
                    (r["scheme"] if r["digestAlgorithm"] == (
                        "sha1" if r["scheme"] in ("gittree", "swhid") else "sha256"
                    ) else f"{r['scheme']}:{r['digestAlgorithm']}") + f"\t{r['value']}\t"
                    + r["path"] + "\n" for r in json_records
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode("utf-8"), expected_text)
                for arguments in [
                    [], [source], ["--unknown", source], ["--h1:sha3", source],
                    ["--h1", "--format=json", "--format=jsonl", source],
                    ["--h1", "--max-depth=-1", source],
                ]:
                    error = self.reject(command, arguments, 2)
                    self.assertIn(b"Usage: dirhash", error.stderr)
                    self.assertIn(b"--h1", error.stderr)
                    self.assertIn(b"Examples:", error.stderr)

    def test_gzip_non_tar_members_remain_opaque(self):
        javascript = gzip.compress(b"/* ordinary compressed JavaScript */\nvar value = 1;\n", mtime=0)
        archive_entries = {"VAADIN/bootstrap.js.gz": ("file", javascript, 0o644)}
        inner = zip_bytes(archive_entries)
        outer_entries = {"library.jar": ("file", inner, 0o644)}
        outer = self.write("gzip-content.zip", zip_bytes(outer_entries))
        tar_entries = {"a": ("file", b"TAR payload", 0o644)}
        extensionless = self.write("gzip-tar.zip", zip_bytes({
            "payload.bin": ("file", gzip.compress(tar_bytes(tar_entries), mtime=0), 0o644),
        }))
        mismatch = self.write("gzip-mismatch.zip", zip_bytes({"bad.tgz": ("file", javascript, 0o644)}))
        for backend, command in self.commands():
            for strict in ([], ["--strict"]):
                with self.subTest(backend=backend, strict=bool(strict)):
                    flags = COMMON_FLAGS + ["--h1-go", "--recurse", "--format=json"] + strict
                    records = self.records(command, flags + [outer])
                    self.assertEqual(len(records), 12)
                    self.check_values(records[:6], outer_entries, outer_entries)
                    self.check_values(records[6:], archive_entries, archive_entries)
                    discovered = self.records(command, flags + [extensionless])
                    self.assertEqual(len(discovered), 12)
                    self.assertEqual(discovered[6]["inputType"], "tar.gz")
                    self.check_values(discovered[6:], tar_entries, tar_entries)
                    self.reject(command, ["--h1", "--recurse"] + strict + [mismatch], 1)

    def test_plain_archive_bytes_and_digest_variants(self):
        entries = {"prefix/a": ("file", b"payload\0bytes", 0o755)}
        archives = [
            self.write("plain-root.zip", zip_bytes(entries)),
            self.write("plain-root.tar", tar_bytes(entries)),
            self.write("plain-root.tgz", gzip.compress(tar_bytes(entries), mtime=0)),
        ]
        selections = ["--plain:" + algorithm for algorithm in DIGESTS]
        blake3_values = {}
        for backend, command in self.commands():
            for source in archives:
                with self.subTest(backend=backend, source=source):
                    payload = Path(source).read_bytes()
                    records = self.records(command, selections + ["--strict", "--format=json", source])
                    self.assertEqual(len(records), len(DIGESTS))
                    self.assertEqual([r["digestAlgorithm"] for r in records], list(DIGESTS))
                    for record in records:
                        self.assertEqual(record["scheme"], "plain")
                        self.assertEqual(record["archiveEntries"], [])
                        algorithm = record["digestAlgorithm"]
                        if algorithm == "blake3":
                            self.assertRegex(record["value"], r"^blake3:[0-9a-f]{64}$")
                            previous = blake3_values.setdefault(source, record["value"])
                            self.assertEqual(record["value"], previous)
                        else:
                            self.assertEqual(record["value"], algorithm + ":" + digest(algorithm, payload).hex())
                    default = self.records(command, ["--plain", "--format=json", source])
                    self.assertEqual(default, [records[1]])
                    projected = self.records(command, [
                        "--plain", "--strip-components=1", "--exclude=prefix/a",
                        "--format=json", source,
                    ])
                    self.assertEqual(projected, default)
                    jsonl = self.records(command, ["--plain", "--format=jsonl", source], jsonl=True)
                    self.assertEqual(jsonl, default)
                    text = self.execute(command, ["--plain", source])
                    self.assertEqual(text.returncode, 0, text.stderr)
                    self.assertEqual(text.stdout.decode(), f"plain\t{default[0]['value']}\t{source}\n")

    def test_plain_recursive_bytes_limits_and_exclusions(self):
        inner = zip_bytes({"x": ("file", b"inner", 0o644)})
        nested_tgz = gzip.compress(tar_bytes({"y": ("file", b"tar data", 0o644)}), mtime=0)
        entries = {
            "a.zip": ("file", inner, 0o644),
            "b.tgz": ("file", nested_tgz, 0o644),
        }
        source = self.write("plain-nested.zip", zip_bytes(entries))
        expanded = len(inner) + len(nested_tgz) + len(b"inner") + len(b"tar data")
        for backend, command in self.commands():
            for strict in ([], ["--strict"]):
                with self.subTest(backend=backend, strict=bool(strict)):
                    flags = ["--plain", "--h1", "--recurse", "--format=json"] + strict
                    records = self.records(command, flags + ["--max-expanded-bytes=" + str(expanded), source])
                    self.assertEqual(len(records), 6)
                    groups = [records[i:i + 2] for i in range(0, len(records), 2)]
                    for group, payload, chain in zip(
                        groups, [Path(source).read_bytes(), inner, nested_tgz], [[], ["a.zip"], ["b.tgz"]],
                    ):
                        self.assertEqual([r["scheme"] for r in group], ["h1", "plain"])
                        self.assertEqual(group[1]["value"], "sha256:" + hashlib.sha256(payload).hexdigest())
                        self.assertEqual(group[1]["archiveEntries"], chain)
                    direct = self.records(command, ["--plain", "--h1", "--format=json", source])
                    self.assertEqual(groups[0], direct)
                    excluded = self.records(command, flags + [
                        "--exclude=a.zip!/x", "--exclude=b.tgz", source,
                    ])
                    self.assertEqual(len(excluded), 4)
                    self.assertEqual(excluded[1], groups[0][1])
                    self.assertEqual(excluded[3], groups[1][1])
                    self.reject(command, flags + ["--max-expanded-bytes=" + str(expanded - 1), source],
                                1, "LIMIT_EXCEEDED")
            directory = self.path / ("directory-" + backend)
            directory.mkdir()
            self.reject(command, ["--plain", "--h1", directory], 3, "UNSUPPORTED_FORMAT")
            ordinary = self.write("not-archive-" + backend, b"ordinary file")
            self.reject(command, ["--plain", ordinary], 3, "UNSUPPORTED_FORMAT")
            damaged = bytearray(inner)
            damaged[14] ^= 1  # The local CRC no longer agrees with the central record.
            corrupt = self.write("plain-corrupt-" + backend + ".zip", bytes(damaged))
            self.reject(command, ["--plain", corrupt], 1)
            outer = self.write("plain-corrupt-nested-" + backend + ".zip",
                               zip_bytes({"bad.zip": ("file", bytes(damaged), 0o644)}))
            self.reject(command, ["--plain", "--recurse", outer], 1)
            trailing = self.write("plain-trailing-" + backend + ".zip", inner + b"junk")
            self.reject(command, ["--plain", trailing], 1, "ARCHIVE_LAYOUT")

    def test_directory_archive_display_paths(self):
        inner = zip_bytes({"x": ("file", b"x", 0o644)})
        directory = self.path / "root!dir"
        (directory / "lib").mkdir(parents=True)
        archive = directory / "lib" / "a!b.jar"
        archive.write_bytes(zip_bytes({"inner!.zip": ("file", inner, 0o644)}))
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, ["--h1", "--recurse", "--format=json", directory])
                self.assertEqual(len(records), 3)
                self.assertEqual(records[0]["path"], str(directory))
                self.assertEqual(records[1]["path"], str(archive))
                self.assertEqual(records[1]["source"], str(directory))
                self.assertEqual(records[1]["archiveEntries"], ["lib/a!b.jar"])
                self.assertEqual(records[2]["path"], str(archive).replace("!", "!!") + "!/inner!!.zip")
                self.assertEqual(records[2]["archiveEntries"], ["lib/a!b.jar", "inner!.zip"])

    def test_archive_acceptance_and_special_entry_diagnostics(self):
        special = single_zip(b"META-INF/maven/", b"", 0, b"", attr=0xffff << 16)
        valid_tar = bytearray(tar_bytes({"PK\x03\x04-file": ("file", b"tar", 0o644)}))
        source = self.write("ambiguous.tar", bytes(valid_tar))
        nested = self.write("ambiguous.zip", zip_bytes({"payload.bin": ("file", bytes(valid_tar), 0o644)}))
        dot_bytes = bytearray(tar_bytes({".": ("dir", b"", 0o755)}))
        dot_bytes[:100] = b"." + bytes(99)
        dot_bytes[148:156] = b" " * 8
        dot_bytes[148:156] = f"{sum(dot_bytes[:512]):06o}\0 ".encode("ascii")
        bare_dot = self.write("bare-dot.tar", bytes(dot_bytes))
        drive = self.write("dot-drive.zip", single_zip(b"./C:x", b"x", 0, b"x"))
        good = zip_bytes({"a": ("file", b"x", 0o644)})
        trailing = self.write("trailing-parity.zip", good + b"junk")
        root = self.path / "special-root"
        root.mkdir()
        bad = root / "invalid.jar"
        bad.write_bytes(special)
        for backend, command in self.commands():
            for strict in ([], ["--strict"]):
                with self.subTest(backend=backend, strict=bool(strict)):
                    self.reject(command, ["--h1"] + strict + [bare_dot], 1, "INVALID_PATH")
                    self.reject(command, ["--h1"] + strict + [drive], 1, "INVALID_PATH")
                    self.reject(command, ["--h1"] + strict + [trailing], 1, "ARCHIVE_LAYOUT")
                    if strict:
                        self.reject(command, ["--h1", "--strict", source], 1, "INVALID_PATH")
                    else:
                        records = self.records(command, ["--h1", "--format=json", source])
                        self.check_values(records, {"PK\x03\x04-file": ("file", b"tar", 0o644)})
                        recursive = self.records(command, ["--h1", "--recurse", "--format=json", nested])
                        self.assertEqual(recursive[1]["value"], records[0]["value"])
                    for target in (bad, root):
                        arguments = ["--h1", "--nar", "--recurse", "--format=json"] + strict + [target]
                        if strict:
                            result = self.reject(command, arguments, 1, "SPECIAL_FILE")
                        else:
                            result = self.execute(command, arguments)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(len(result.stderr.decode().splitlines()), 1)
                            self.assertTrue(result.stderr.startswith(b"WARN_ZIP_DIRECTORY_MODE:"))
                            records = json.loads(result.stdout)["results"]
                            archive_records = [r for r in records if r["inputType"] == "zip"]
                            self.assertEqual(len(archive_records), 2)
                            self.check_values(archive_records, {"META-INF/maven": ("dir", b"", 0o777)})
                        error = result.stderr.decode()
                        self.assertIn("META-INF/maven/", error)
                        self.assertIn("177777", error)
                        if strict:
                            self.assertIn("170000", error)
                        self.assertIn(str(bad), error)
                        if os.name == "nt":
                            self.assertNotIn("\\\\", error)
            for name, payload, mode in [
                (b"META-INF/maven/", b"x", 0xffff),
                (b"META-INF/maven", b"", 0xffff),
                (b"META-INF/maven/", b"", 0xf1ff),
            ]:
                invalid = self.write("not-legacy.zip", single_zip(name, payload, 0, payload, attr=mode << 16))
                self.reject(command, ["--h1", invalid], 1, "SPECIAL_FILE")

    def test_zip_repeated_trailing_directory_slashes(self):
        originals = {
            "9/java.activation//": ("dir", b"", 0o755),
            "9/java.activation/module-info.sig": ("file", b"signature", 0o644),
        }
        logical = {
            "9/java.activation": ("dir", b"", 0o755),
            "9/java.activation/module-info.sig": ("file", b"signature", 0o644),
        }
        data = zip_bytes(originals)
        source = self.write("symbols.zip", data)
        nested = self.write("runtime.zip", zip_bytes({"ct.sym": ("file", data, 0o644)}))
        flags = COMMON_FLAGS + ["--h1-go", "--plain", "--format=json"]
        for backend, command in self.commands():
            for target, recurse in ((source, []), (nested, ["--recurse"])):
                with self.subTest(backend=backend, target=target):
                    result = self.execute(command, flags + recurse + [target])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    warning = result.stderr.decode()
                    self.assertEqual(len(warning.splitlines()), 1)
                    self.assertTrue(warning.startswith("WARN_ZIP_DIRECTORY_SLASH: "), warning)
                    self.assertIn("9/java.activation//", warning)
                    self.assertTrue(warning.endswith(
                        ": accepted empty ZIP directory with repeated trailing slashes\n"))
                    records = json.loads(result.stdout)["results"]
                    selected = [r for r in records if r["source"] == target and
                                r["archiveEntries"] == ([] if target == source else ["ct.sym"])]
                    self.assertEqual(len(selected), len(flags) - 1)
                    self.check_values([r for r in selected if r["scheme"] != "plain"],
                                      logical, originals)
                    self.assertEqual([r["value"] for r in selected if r["scheme"] == "plain"],
                                     ["sha256:" + hashlib.sha256(data).hexdigest()])
                    rejected = self.reject(command, flags + recurse + ["--strict", target],
                                           1, "INVALID_PATH")
                    self.assertNotIn(b"WARN_", rejected.stderr)
            for name, payload in [
                (b"a//b/", b""), (b"//", b""), (b"/a//", b""),
                (b"a/./b//", b""), (b"a//", b"x"),
            ]:
                invalid = self.write("invalid-slashes.zip",
                                     single_zip(name, payload, 0, payload,
                                                attr=(stat.S_IFDIR | 0o755) << 16))
                result = self.reject(command, ["--h1", invalid], 1)
                self.assertNotIn(b"WARN_", result.stderr)

    def test_http_download_and_limit(self):
        data = zip_bytes({"remote": ("file", b"response", 0o644)})
        probe = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/probe":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                        self.wfile.write(data[:16])
                        self.wfile.flush()
                        deadline = time.monotonic() + 10
                        while time.monotonic() < deadline:
                            temporary = [p.name for p in probe["temp"].iterdir()]
                            if temporary or list(probe["cwd"].iterdir()):
                                break
                            time.sleep(0.02)
                        probe["seen"] = (temporary, [p.name for p in probe["cwd"].iterdir()])
                        self.wfile.write(data[16:])
                    return
                if self.path in ("/redirect", "/loop"):
                    self.send_response(302)
                    self.send_header("Location", "/archive.zip" if self.path == "/redirect" else "/loop")
                    self.end_headers()
                    return
                if self.path == "/missing":
                    self.send_error(404)
                    return
                self.send_response(200)
                if self.path == "/encoded":
                    self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(data) + (1 if self.path == "/truncated" else 0)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(data)

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_port}"
        for backend, command in self.commands():
            with self.subTest(backend=backend):
                records = self.records(command, ["--h1", "--format=json", url + "/redirect"])
                self.check_values(records, {"remote": ("file", b"response", 0o644)})
                self.assertEqual(records[0]["source"], url + "/redirect")
                plain = self.records(command, ["--plain", "--format=json", url + "/redirect"])
                self.assertEqual(plain[0]["value"], "sha256:" + hashlib.sha256(data).hexdigest())
                self.reject(command, ["--h1", "--max-download-bytes=1", url + "/archive.zip"], 1)
                self.reject(command, ["--h1", url + "/encoded"], 4)
                self.reject(command, ["--h1", url + "/loop"], 4)
                self.reject(command, ["--h1", url + "/missing"], 4)
                self.reject(command, ["--h1", url + "/truncated"], 4)
                workdir = self.path / f"cwd-{backend}"
                workdir.mkdir()
                for arguments in (["--h1"], ["--plain"], ["--h1", "--max-download-bytes=1"]):
                    self.execute(command, arguments + [url + "/redirect"], cwd=workdir)
                self.assertEqual(list(workdir.iterdir()), [], "download temporary files leaked")
                temp = self.path / f"temp-{backend}"
                temp.mkdir()
                probe.update(temp=temp, cwd=workdir)
                probe.pop("seen", None)
                env = dict(os.environ, TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp))
                probe_command = list(command)
                if backend == "java":
                    probe_command[1:1] = ["-XX:-UsePerfData", f"-Djava.io.tmpdir={temp}"]
                result = self.execute(probe_command, ["--plain", "--format=json", url + "/probe"],
                                      cwd=workdir, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                in_temp, in_cwd = probe["seen"]
                self.assertEqual(in_cwd, [], "download written to the working directory")
                self.assertEqual(len(in_temp), 1, "download not in the OS temporary directory")
                self.assertTrue(in_temp[0].startswith((".dirhash-download-", "dirhash-download-")),
                                in_temp[0])
                self.assertEqual(list(temp.iterdir()), [], "download temporary files leaked")
                self.assertEqual(list(workdir.iterdir()), [], "download temporary files leaked")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("all", "java", "go"), default="all")
    parser.add_argument("--java", type=Path, default=ROOT / "dist" / "java" / "dirhash.jar")
    machine = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
    go_default = ROOT / "dist" / "go" / (
        "dirhash-windows-amd64.exe" if os.name == "nt" else f"dirhash-linux-{machine}"
    )
    parser.add_argument("--go", type=Path, default=go_default)
    args, unittest_args = parser.parse_known_args()
    if args.backend in ("all", "java"):
        Conformance.backends["java"] = ["java", "-jar", str(args.java.resolve())]
    if args.backend in ("all", "go"):
        Conformance.backends["go"] = [str(args.go.resolve())]
    unittest.main(argv=[sys.argv[0]] + unittest_args)


if __name__ == "__main__":
    main()
