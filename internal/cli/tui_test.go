package cli

import (
	"strings"
	"testing"
)

func TestFullScreenSessionEntersAndRestoresTheTerminal(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	r := alice.interactive(t, nil, []exchange{{`1 Secrets`, "q"}}, ptyOptions{stdoutIsTerminal: true})
	ok(t, r.result)
	if !strings.Contains(r.stderr, "\x1b[?1049h") || !strings.Contains(r.stderr, "\x1b[?1049l") {
		t.Fatalf("%q", r.stderr)
	}
	if strings.LastIndex(r.stderr, "\x1b[?1049l") < strings.LastIndex(r.stderr, "\x1b[?1049h") {
		t.Fatal("the alternate screen is not left at the end")
	}
}

func TestFullScreenSessionDecodesKeysSplitAcrossReads(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	// Every answer is a separate write, so a separate read: a left arrow and a UTF-8 character in two parts.
	var exchanges []exchange
	for index, chunk := range []string{"a", "XY", "\x1b[", "D", "Z", "\r", "\xc3", "\xa9", "\r"} {
		prompt := ""
		if index == 0 {
			prompt = `1 Secrets`
		}
		exchanges = append(exchanges, exchange{prompt, chunk})
	}
	// A lone Escape is the Escape key once nothing follows it; "^" waits before typing q.
	exchanges = append(exchanges, exchange{`Set XZY`, "\x1b"}, exchange{`^`, "q"})
	r := alice.interactive(t, []string{"tui"}, exchanges, ptyOptions{stdoutIsTerminal: true})
	ok(t, r.result)
	if got := alice.run(t, []string{"get", "XZY"}).stdout; got != "é" {
		t.Fatalf("%q; screen %q", got, r.screen)
	}
}
