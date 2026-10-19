package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

const version = "dirhash 0.1.0\n"
const usage = "Usage: dirhash HASH_SELECTION... [options] INPUT\n"
const quickUsage = usage + `Select at least one hash: --h1 --h1-go --gittree --swhid --nar --plain
Examples:
  dirhash --h1 .
  dirhash --h1-go library.jar
  dirhash --h1 --gittree --strict archive.zip
Use --help for all options.
`
const help = usage + `
Selections: --h1 --h1-go --gittree --swhid --nar --plain
Each selection accepts :DIGEST. Digests:
sha1 sha256 sha512 blake2b-256 blake2b-512 blake3 sha3-256 sha3-512

Options:
  --strict --recurse
  --exclude=PATTERN             Repeatable, root-anchored exclusions
  --strip-components=N          Strip the original archive prefix only
  --format=text|json|jsonl
  --max-depth=N                 Default 16
  --max-entries=N               Default 1000000
  --max-expanded-bytes=N        Default 107374182400
  --max-download-bytes=N        Default 10737418240
Limits accept non-negative decimals or unlimited.
  --help --version --

ZIP methods: stored (0), DEFLATE (8), BZIP2 (12),
Zstandard (20,93), XZ (95). Deflate64, ZIP-LZMA and PPMd unsupported.
TAR (ustar/PAX/GNU, sparse), TAR.GZ, directories and HTTP(S) archives.
SHA-1 is provided for interoperability, not publisher authentication.

` + quickUsage

var schemes = []string{"h1", "h1-go", "gittree", "swhid", "nar", "plain"}
var algorithms = []string{"sha1", "sha256", "sha512", "blake2b-256", "blake2b-512", "blake3", "sha3-256", "sha3-512"}

type selection struct{ scheme, algorithm string }
type options struct {
	ctx                                context.Context
	source, format                     string
	selected                           []selection
	excludes                           []pattern
	strict, recurse                    bool
	stripSet                           bool
	strip                              uint64
	depth, entries, expanded, download uint64
}
type failure struct {
	code, location, reason string
	status                 int
}

func (e *failure) Error() string {
	location := e.location
	if strings.HasPrefix(strings.ToLower(location), "http:") || strings.HasPrefix(strings.ToLower(location), "https:") {
		if i := strings.IndexAny(location, "?#"); i >= 0 {
			location = location[:i] + "[redacted]"
		}
	}
	return e.code + " " + diagnosticText(location) + ": " + strconv.QuoteToASCII(e.reason)
}
func diagnosticText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			_, _ = fmt.Fprintf(&b, "\\u{%x}", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func fail(code, location, reason string) error {
	status := 1
	if strings.HasPrefix(code, "UNSUPPORTED_") {
		status = 3
	}
	if code == "IO_ERROR" || code == "NETWORK_ERROR" {
		status = 4
	}
	return &failure{code, location, reason, status}
}
func quote(s string) string { return strconv.QuoteToASCII(s) }
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func number(s string, unlimited bool) (uint64, error) {
	if unlimited && s == "unlimited" {
		return ^uint64(0), nil
	}
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("expected a non-negative decimal integer")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errors.New("integer overflow")
	}
	return n, nil
}
func parse(args []string) (*options, error) {
	o := &options{format: "text", depth: 16, entries: 1000000, expanded: 107374182400, download: 10737418240}
	seen := map[string]bool{}
	sels := map[selection]bool{}
	positional := false
	haveInput := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !positional && a == "--" {
			positional = true
			continue
		}
		if !positional && strings.HasPrefix(a, "-") {
			if !strings.HasPrefix(a, "--") {
				return nil, fmt.Errorf("unknown option %s", quote(a))
			}
			name, value, hasValue := strings.Cut(a[2:], "=")
			scheme, digest, qualifier := strings.Cut(name, ":")
			if contains(schemes, scheme) {
				if hasValue {
					return nil, errors.New("digest selections use colon syntax")
				}
				if !qualifier {
					digest = "sha256"
					if scheme == "gittree" || scheme == "swhid" {
						digest = "sha1"
					}
				}
				if !contains(algorithms, digest) {
					return nil, fmt.Errorf("unknown digest %s", quote(digest))
				}
				sels[selection{scheme, digest}] = true
				continue
			}
			if name == "strict" || name == "recurse" {
				if hasValue || seen[name] {
					return nil, fmt.Errorf("invalid or repeated --%s", name)
				}
				seen[name] = true
				if name == "strict" {
					o.strict = true
				} else {
					o.recurse = true
				}
				continue
			}
			if !contains([]string{"exclude", "format", "strip-components", "max-depth", "max-entries", "max-expanded-bytes", "max-download-bytes"}, name) {
				return nil, fmt.Errorf("unknown option %s", quote(a))
			}
			if name != "exclude" && seen[name] {
				return nil, fmt.Errorf("repeated --%s", name)
			}
			seen[name] = true
			if !hasValue {
				i++
				if i == len(args) {
					return nil, fmt.Errorf("missing --%s value", name)
				}
				value = args[i]
			}
			switch name {
			case "exclude":
				p, e := compilePattern(value)
				if e != nil {
					return nil, e
				}
				o.excludes = append(o.excludes, p)
			case "format":
				if !contains([]string{"text", "json", "jsonl"}, value) {
					return nil, errors.New("invalid output format")
				}
				o.format = value
			default:
				n, e := number(value, name != "strip-components")
				if e != nil {
					return nil, fmt.Errorf("--%s: %w", name, e)
				}
				switch name {
				case "strip-components":
					o.strip = n
					o.stripSet = true
				case "max-depth":
					o.depth = n
				case "max-entries":
					o.entries = n
				case "max-expanded-bytes":
					o.expanded = n
				case "max-download-bytes":
					o.download = n
				}
			}
		} else {
			if haveInput {
				return nil, errors.New("exactly one input is required")
			}
			o.source = a
			haveInput = true
		}
	}
	if !haveInput || o.source == "" {
		return nil, errors.New("exactly one explicit input is required")
	}
	if len(sels) == 0 {
		return nil, errors.New("at least one hash selection is required")
	}
	for _, s := range schemes {
		for _, d := range algorithms {
			v := selection{s, d}
			if sels[v] {
				o.selected = append(o.selected, v)
			}
		}
	}
	return o, nil
}

type record struct {
	Path            string   `json:"path"`
	Source          string   `json:"source"`
	ArchiveEntries  []string `json:"archiveEntries"`
	InputType       string   `json:"inputType"`
	Scheme          string   `json:"scheme"`
	DigestAlgorithm string   `json:"digestAlgorithm"`
	Value           string   `json:"value"`
}

func jsonString(s string) string {
	return escapedPath(s, true)
}
func textPath(s string) string {
	return escapedPath(s, false)
}
func escapedPath(s string, quoted bool) string {
	var b strings.Builder
	if quoted {
		b.WriteByte('"')
	}
	for _, r := range s {
		switch r {
		case '"', '\\':
			if quoted {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				_, _ = fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	if quoted {
		b.WriteByte('"')
	}
	return b.String()
}
func writeRecord(b *bytes.Buffer, r record) {
	b.WriteString(`{"path":`)
	b.WriteString(jsonString(r.Path))
	b.WriteString(`,"source":`)
	b.WriteString(jsonString(r.Source))
	b.WriteString(`,"archiveEntries":[`)
	for i, p := range r.ArchiveEntries {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(p))
	}
	b.WriteString(`],"inputType":`)
	b.WriteString(jsonString(r.InputType))
	b.WriteString(`,"scheme":`)
	b.WriteString(jsonString(r.Scheme))
	b.WriteString(`,"digestAlgorithm":`)
	b.WriteString(jsonString(r.DigestAlgorithm))
	b.WriteString(`,"value":`)
	b.WriteString(jsonString(r.Value))
	b.WriteByte('}')
}
func publish(o *options, records []record) []byte {
	var b bytes.Buffer
	switch o.format {
	case "json":
		b.WriteString(`{"schemaVersion":1,"results":[`)
		for i, r := range records {
			if i > 0 {
				b.WriteByte(',')
			}
			writeRecord(&b, r)
		}
		b.WriteString("]}\n")
	case "jsonl":
		for _, r := range records {
			writeRecord(&b, r)
			b.WriteByte('\n')
		}
	default:
		for _, r := range records {
			label := r.Scheme
			defaultDigest := "sha256"
			if r.Scheme == "gittree" || r.Scheme == "swhid" {
				defaultDigest = "sha1"
			}
			if r.DigestAlgorithm != defaultDigest {
				label += ":" + r.DigestAlgorithm
			}
			_, _ = fmt.Fprintf(&b, "%s\t%s\t%s\n", label, r.Value, textPath(r.Path))
		}
	}
	return b.Bytes()
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	status := runContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(status)
}
func run(args []string, out, errOut io.Writer) int {
	return runContext(context.Background(), args, out, errOut)
}
func runContext(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "--version") {
		s := help
		if args[0] == "--version" {
			s = version
		}
		if n, e := io.WriteString(out, s); e != nil || n != len(s) {
			_, _ = fmt.Fprint(errOut, "IO_ERROR: failed to write CLI output.\n")
			return 4
		}
		return 0
	}
	o, e := parse(args)
	if e != nil {
		_, _ = fmt.Fprintf(errOut, "USAGE_ERROR: %s\n%s", e, quickUsage)
		return 2
	}
	o.ctx = ctx
	engine := newEngine(o)
	records, e := engine.execute()
	if e != nil {
		var f *failure
		if !errors.As(e, &f) {
			f = &failure{"IO_ERROR", o.source, e.Error(), 4}
		}
		_, _ = fmt.Fprintln(errOut, f.Error())
		return f.status
	}
	for _, warning := range engine.warningMessages() {
		if _, writeErr := fmt.Fprintln(errOut, warning); writeErr != nil {
			_, _ = fmt.Fprint(errOut, "IO_ERROR: failed to write CLI warning.\n")
			return 4
		}
	}
	publication := publish(o, records)
	if n, writeErr := out.Write(publication); writeErr != nil || n != len(publication) {
		_, _ = fmt.Fprint(errOut, "IO_ERROR: failed to write CLI output.\n")
		return 4
	}
	return 0
}
func sortedKeys[T any](m map[string]T) []string {
	a := make([]string, 0, len(m))
	for k := range m {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}
