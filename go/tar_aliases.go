package main

import (
	"bufio"
	"io"
)

type aliasPass struct {
	entry     *entry
	namespace *namespace
	writer    *io.PipeWriter
	done      chan error
}

func pendingAliases(n *namespace, target *entry) []*entry {
	var result []*entry
	for _, name := range sortedKeys(n.original) {
		alias := n.original[name]
		if alias.kind != 'h' || !alias.included {
			continue
		}
		path := alias.hardlink
		seen := map[string]bool{alias.original: true}
		for path != target.original {
			next := n.original[path]
			if seen[path] || next == nil || next.kind != 'h' {
				break
			}
			seen[path] = true
			path = next.hardlink
		}
		if path == target.original {
			result = append(result, alias)
		}
	}
	return result
}

func (e *engine) tarPayload(n *namespace, target *entry, source io.Reader) error {
	if target.seekOnly || (!e.o.strict && !e.o.recurse) {
		return e.payload(n, target, source, true, true)
	}
	aliases := pendingAliases(n, target)
	if len(aliases) == 0 {
		return e.payload(n, target, source, true, true)
	}
	buffer := bufio.NewReaderSize(source, 65536)
	typ, _ := detect(buffer, "", false)
	selected := aliases[:0]
	for _, alias := range aliases {
		if typ != "" || suffixType(alias.original) != "" {
			selected = append(selected, alias)
		}
	}
	if len(selected) > 1024 {
		return fail("LIMIT_EXCEEDED", n.location(), "forward archive aliases exceed bounded simultaneous decoder representation")
	}
	var passes []aliasPass
	var writers []io.Writer
	for _, alias := range selected {
		copyEntry := *alias
		copyEntry.kind = 'f'
		copyEntry.size = target.size
		copyEntry.open = target.open
		copyNamespace := *n
		copyNamespace.children = nil
		reader, writer := io.Pipe()
		pass := aliasPass{entry: alias, namespace: &copyNamespace, writer: writer, done: make(chan error, 1)}
		go func() {
			err := e.payload(&copyNamespace, &copyEntry, reader, false, true)
			_ = reader.CloseWithError(err)
			pass.done <- err
		}()
		passes = append(passes, pass)
		writers = append(writers, writer)
	}
	if len(passes) == 0 {
		return e.payload(n, target, buffer, true, true)
	}
	err := e.payload(n, target, io.TeeReader(buffer, io.MultiWriter(writers...)), true, true)
	for _, pass := range passes {
		_ = pass.writer.CloseWithError(err)
	}
	var aliasError error
	for _, pass := range passes {
		if result := <-pass.done; result != nil && aliasError == nil {
			aliasError = result
		}
		n.children = append(n.children, pass.namespace.children...)
		pass.entry.aliasDiscovered = true
	}
	if aliasError != nil {
		return aliasError
	}
	return err
}
