// Package termui holds what the CLI and the terminal UI both draw with:
// colors, symbols (with an ASCII fallback), sanitizing, and column layout.
package termui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/k18k/msecrets/internal/core"
)

// Style wraps text in an SGR sequence (or returns it unchanged without colors).
type Style func(string) string

// Colors are the styles of one output stream.
type Colors struct {
	Bold, Dim, Red, Green, Yellow, Blue, Magenta, Cyan, Inverse Style
}

// ColorsEnabled follows NO_COLOR, then FORCE_COLOR, then whether the stream is a terminal (and TERM is not dumb).
func ColorsEnabled(isTerminal bool, getenv func(string) (string, bool)) bool {
	if value, _ := getenv("NO_COLOR"); value != "" {
		return false
	}
	if value, ok := getenv("FORCE_COLOR"); ok {
		return value != "0"
	}
	term, _ := getenv("TERM")
	return isTerminal && term != "dumb"
}

// NewColors returns styles that color only when enabled. Each style closes only
// its own attribute, so styles nest (bold inside inverse).
func NewColors(enabled bool) Colors {
	wrap := func(open, close string) Style {
		return func(text string) string {
			if !enabled {
				return text
			}
			return "\x1b[" + open + "m" + text + "\x1b[" + close + "m"
		}
	}
	return Colors{
		Bold: wrap("1", "22"), Dim: wrap("2", "22"),
		Red: wrap("31", "39"), Green: wrap("32", "39"), Yellow: wrap("33", "39"),
		Blue: wrap("34", "39"), Magenta: wrap("35", "39"), Cyan: wrap("36", "39"),
		Inverse: wrap("7", "27"),
	}
}

// SupportsUnicode: legacy Windows consoles lack the glyphs; modern terminals everywhere have them.
func SupportsUnicode(getenv func(string) (string, bool), platform string) bool {
	value := func(key string) string { v, _ := getenv(key); return v }
	if platform != "windows" {
		return value("TERM") != "linux"
	}
	return value("WT_SESSION") != "" || value("TERMINUS_SUBLIME") != "" || value("ConEmuTask") != "" ||
		value("TERM_PROGRAM") == "vscode" || strings.HasPrefix(value("TERM"), "xterm")
}

// Symbols are the glyphs of the UI.
type Symbols struct {
	Cell                                    map[core.CellState]string
	Check, Cross, Arrow, Bullet, Line, Mask string
	Unicode                                 bool
}

// NewSymbols returns Unicode glyphs, or ASCII ones for legacy consoles.
func NewSymbols(unicode bool) Symbols {
	if unicode {
		return Symbols{
			Cell: map[core.CellState]string{core.StateOK: "●", core.StateStale: "◐", core.StateMissing: "○",
				core.StateInvalid: "✗", core.StateUnexpected: "!", core.StateAbsent: "·"},
			Check: "✓", Cross: "✗", Arrow: "›", Bullet: "•", Line: "─", Mask: "•", Unicode: true,
		}
	}
	return Symbols{
		Cell: map[core.CellState]string{core.StateOK: "+", core.StateStale: "~", core.StateMissing: "-",
			core.StateInvalid: "x", core.StateUnexpected: "!", core.StateAbsent: "."},
		Check: "+", Cross: "x", Arrow: ">", Bullet: "*", Line: "-", Mask: "*",
	}
}

// CellStyle colors a cell glyph by state.
func CellStyle(c Colors, state core.CellState) Style {
	switch state {
	case core.StateOK:
		return c.Green
	case core.StateStale:
		return c.Yellow
	case core.StateAbsent:
		return c.Dim
	}
	return c.Red
}

// CellDescriptions explain the cell glyphs (legend).
var CellDescriptions = map[core.CellState]string{
	core.StateOK: "set", core.StateStale: "needs sync", core.StateMissing: "missing",
	core.StateInvalid: "bad signature", core.StateUnexpected: "unexpected", core.StateAbsent: "n/a",
}

// LegendStates are the states shown in legends, in order.
var LegendStates = []core.CellState{core.StateOK, core.StateStale, core.StateMissing, core.StateInvalid}

// Sanitize makes untrusted text safe to print: control characters (escape sequences) become U+FFFD.
func Sanitize(text string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
			return '�'
		}
		return r
	}, text)
}

// Width is the display width of text, ignoring ANSI sequences.
func Width(text string) int { return ansi.StringWidth(text) }

// PadEnd pads text with spaces to a display width.
func PadEnd(text string, width int) string {
	return text + strings.Repeat(" ", max(0, width-Width(text)))
}

// Fit truncates text to a display width (ANSI-aware, ending in …) and pads it to exactly that width.
func Fit(text string, width int) string {
	if Width(text) <= width {
		return PadEnd(text, width)
	}
	truncated := ansi.Truncate(text, width, "…")
	return PadEnd(truncated+"\x1b[0m", width)
}

// Table renders rows as aligned columns.
func Table(rows [][]string) []string {
	const gap = 2
	var widths []int
	for _, row := range rows {
		for index, cell := range row {
			if index >= len(widths) {
				widths = append(widths, 0)
			}
			widths[index] = max(widths[index], Width(cell))
		}
	}
	lines := make([]string, len(rows))
	for r, row := range rows {
		var b strings.Builder
		for index, cell := range row {
			if index == len(row)-1 {
				b.WriteString(cell)
			} else {
				b.WriteString(PadEnd(cell, widths[index]+gap))
			}
		}
		lines[r] = strings.TrimRight(b.String(), " ")
	}
	return lines
}
