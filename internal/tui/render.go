package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/k18k/msecrets/internal/core"
	"github.com/k18k/msecrets/internal/termui"
)

// Run runs the full-screen UI until the user quits.
func Run(app *App) error {
	_, err := tea.NewProgram(app).Run()
	return err
}

func (a *App) hints() string {
	switch a.view {
	case secretsView:
		return "enter edit · v reveal · a add · r rename · d delete · u unset · D describe · s sync · / filter · ? help · q quit"
	case environmentsView:
		return "a add · r rename · d remove · g grant · x revoke · s sync · ? help · q quit"
	case recipientsView:
		return "a add · r rename · d remove · g grant · x revoke · D describe · ? help · q quit"
	}
	return "enter go to · s sync · ? help · q quit"
}

// render draws the screen as exactly height lines of at most width columns.
func (a *App) render(width, height int) []string {
	c, s := a.Colors, a.Symbols
	me := a.mine()
	errorCount := 0
	for _, finding := range a.report.Findings {
		if finding.Level == core.LevelError {
			errorCount++
		}
	}
	warnings := len(a.report.Findings) - errorCount

	who := "no identity"
	if len(me) > 0 {
		who = "you: " + strings.Join(me, ", ")
	} else if len(a.Identities) > 0 {
		who = "not a recipient"
	}
	var tabs []string
	for index, title := range viewTitles {
		label := fmt.Sprintf(" %d %s ", index+1, title)
		if view(index) == a.view {
			tabs = append(tabs, c.Inverse(label))
		} else {
			tabs = append(tabs, c.Dim(label))
		}
	}
	tabLine := strings.Join(tabs, " ")
	if a.filter != "" {
		tabLine += c.Yellow("   filter: " + a.filter)
	}
	header := []string{
		c.Inverse(c.Bold(" msecrets ")) + " " + a.fileLabel() + "  " + c.Dim(who),
		tabLine,
		c.Dim(strings.Repeat(s.Line, width)),
	}

	health := c.Green(s.Check + " all values present, current, and signed")
	if errorCount > 0 || warnings > 0 {
		var parts []string
		if errorCount > 0 {
			parts = append(parts, c.Red(fmt.Sprintf("%d error(s)", errorCount)))
		}
		if warnings > 0 {
			parts = append(parts, c.Yellow(fmt.Sprintf("%d warning(s)", warnings)))
		}
		health = strings.Join(parts, c.Dim(" · "))
	}
	var legend []string
	for _, state := range termui.LegendStates {
		legend = append(legend, termui.CellStyle(c, state)(s.Cell[state])+" "+termui.CellDescriptions[state])
	}
	statusLine := ""
	if a.status != nil {
		style := c.Cyan
		switch a.status.tone {
		case toneError:
			style = c.Red
		case toneSuccess:
			style = c.Green
		}
		statusLine = style(termui.Sanitize(a.status.text))
	}
	footer := []string{
		c.Dim(strings.Repeat(s.Line, width)),
		strings.Join(legend, "  ") + "   " + health,
		c.Dim(a.hints()),
		statusLine,
	}

	bodyHeight := max(1, height-len(header)-len(footer))
	body := a.body(bodyHeight, width)
	for len(body) < bodyHeight {
		body = append(body, "")
	}
	lines := append(append(header, body[:bodyHeight]...), footer...)
	lines = lines[:min(len(lines), height)]
	for index, line := range lines {
		lines[index] = termui.Fit(line, width)
	}
	if top := a.top(); top != nil {
		return a.overlay(lines, top, width, height)
	}
	return lines
}

// window keeps the selected row visible and returns the visible rows.
func (a *App) window(rows []string, height int) []string {
	if a.row < a.scroll {
		a.scroll = a.row
	} else if a.row >= a.scroll+height {
		a.scroll = a.row - height + 1
	}
	a.scroll = max(0, min(a.scroll, max(0, len(rows)-height)))
	return rows[a.scroll:min(len(rows), a.scroll+max(0, height))]
}

func (a *App) body(height, width int) []string {
	c, s := a.Colors, a.Symbols
	marker := func(selected bool) string {
		if selected {
			return c.Cyan(s.Arrow + " ")
		}
		return "  "
	}
	pad := termui.PadEnd

	switch a.view {
	case secretsView:
		secrets, environments := a.secrets(), a.environments()
		if len(secrets) == 0 {
			if a.filter != "" {
				return []string{fmt.Sprintf("  No secrets match \"%s\" (esc clears the filter)", a.filter)}
			}
			return []string{"  No secrets yet. Press a to add one."}
		}
		longest := 8
		for _, name := range secrets {
			longest = max(longest, len(name))
		}
		nameWidth := min(longest+2, max(12, width/3))
		columnWidths := make([]int, len(environments))
		head := "  " + pad(c.Bold("SECRET"), nameWidth)
		for index, name := range environments {
			columnWidths[index] = max(len(name), 3) + 2
			head += pad(c.Bold(name), columnWidths[index])
		}
		head += c.Bold("DESCRIPTION")
		rows := make([]string, len(secrets))
		for rowIndex, name := range secrets {
			var cells strings.Builder
			for columnIndex, environment := range environments {
				state := a.cell(name, environment)
				glyph := termui.CellStyle(c, state)(s.Cell[state])
				// Brackets keep the selection visible without colors (NO_COLOR, monochrome terminals).
				if rowIndex == a.row && columnIndex == a.column {
					cells.WriteString(pad(c.Inverse("["+glyph+"]"), columnWidths[columnIndex]))
				} else {
					cells.WriteString(pad(" "+glyph+" ", columnWidths[columnIndex]))
				}
			}
			label := termui.Fit(name, nameWidth-1)
			if rowIndex == a.row {
				label = c.Bold(label)
			}
			entry, _ := a.document.Secrets.Get(name)
			rows[rowIndex] = marker(rowIndex == a.row) + pad(label, nameWidth) + cells.String() + c.Dim(entry.Description)
		}
		return append([]string{head}, a.window(rows, height-1)...)

	case environmentsView:
		rows := make([]string, 0, len(a.environments()))
		for index, name := range a.environments() {
			ok, total := 0, 0
			for _, cell := range a.report.Cells {
				if cell.Environment == name && cell.State != core.StateAbsent {
					total++
					if cell.State == core.StateOK {
						ok++
					}
				}
			}
			count := c.Yellow(fmt.Sprintf("%d/%d", ok, total))
			if ok == total {
				count = c.Green(fmt.Sprintf("%d/%d", ok, total))
			}
			recipients := strings.Join(a.recipientsOf(name), ", ")
			if recipients == "" {
				recipients = c.Yellow("no recipients")
			}
			rows = append(rows, marker(index == a.row)+pad(name, 20)+pad(count, 10)+recipients)
		}
		head := "  " + pad(c.Bold("ENVIRONMENT"), 20) + pad(c.Bold("VALUES"), 10) + c.Bold("RECIPIENTS")
		return append([]string{head}, a.window(rows, height-1)...)

	case recipientsView:
		mine := a.mine()
		rows := make([]string, 0, len(a.recipients()))
		for index, name := range a.recipients() {
			key, err := core.RecipientKey(a.document, name)
			kind := "invalid key"
			if err == nil {
				kind = string(key.Kind)
				if key.SigningKey == nil {
					kind += " (read-only)"
				}
			}
			var environments []string
			for _, environment := range a.environments() {
				for _, member := range a.recipientsOf(environment) {
					if member == name {
						environments = append(environments, environment)
					}
				}
			}
			label := name
			for _, own := range mine {
				if own == name {
					label += c.Cyan(" (you)")
				}
			}
			list := strings.Join(environments, ", ")
			if list == "" {
				list = c.Dim("none")
			}
			entry, _ := a.document.Recipients.Get(name)
			rows = append(rows, marker(index == a.row)+pad(label, 26)+pad(kind, 28)+pad(list, 30)+c.Dim(entry.Description))
		}
		head := "  " + pad(c.Bold("RECIPIENT"), 26) + pad(c.Bold("KEY"), 28) + pad(c.Bold("ENVIRONMENTS"), 30) + c.Bold("DESCRIPTION")
		return append([]string{head}, a.window(rows, height-1)...)
	}

	if len(a.report.Findings) == 0 {
		return []string{c.Green("  " + s.Check + " Every value is present, current, and signed.")}
	}
	rows := make([]string, len(a.report.Findings))
	for index, finding := range a.report.Findings {
		label := c.Yellow("warning")
		if finding.Level == core.LevelError {
			label = c.Red("error  ")
		}
		rows[index] = marker(index == a.row) + label + " " + finding.Message
	}
	return a.window(rows, height)
}

func (a *App) modalContent(m *modal, inner int) (string, []string) {
	c := a.Colors
	switch m.kind {
	case helpModal:
		var lines []string
		for _, row := range helpRows {
			lines = append(lines, termui.PadEnd(c.Cyan(row[0]), 14)+row[1])
		}
		return "Keys", append(lines, "", c.Dim("any key closes"))
	case messageModal:
		return m.title, m.lines
	case confirmModal:
		return m.title, append(append([]string{}, m.lines...), "", c.Dim("y confirm · n / esc cancel"))
	case pickModal:
		var lines []string
		for index, option := range m.options {
			if index == m.index {
				lines = append(lines, c.Inverse(" "+option+" "))
			} else {
				lines = append(lines, " "+option+" ")
			}
		}
		return m.title, append(lines, "", c.Dim("↑↓ choose · enter select · esc cancel"))
	}
	// One display character per code point keeps the cursor aligned; control characters
	// in a value (escape sequences) are shown, never sent to the terminal.
	chars := make([]string, len(m.value))
	for index, r := range m.value {
		if m.hidden && !m.revealed {
			chars[index] = a.Symbols.Mask
		} else {
			chars[index] = termui.Sanitize(string(r))
		}
	}
	fieldWidth := max(4, inner-2)
	start := max(0, m.cursor-fieldWidth+1)
	visible := chars[start:min(len(chars), start+fieldWidth)]
	cursor := m.cursor - start
	under := " "
	if cursor < len(visible) {
		under = visible[cursor]
	}
	field := strings.Join(visible[:min(cursor, len(visible))], "") + c.Inverse(under)
	if cursor+1 < len(visible) {
		field += strings.Join(visible[cursor+1:], "")
	}
	return m.title, []string{c.Cyan(a.Symbols.Arrow) + " " + field, "", c.Dim(m.hint)}
}

func (a *App) overlay(lines []string, m *modal, width, height int) []string {
	boxWidth := max(20, min(width-2, 76))
	inner := boxWidth - 4
	title, content := a.modalContent(m, inner)
	h, v, tl, tr, bl, br := "-", "|", "+", "+", "+", "+"
	if a.Symbols.Unicode {
		h, v, tl, tr, bl, br = "─", "│", "┌", "┐", "└", "┘"
	}
	titleText := " " + strings.TrimRight(termui.Fit(termui.Sanitize(title), inner-2), " ") + " "
	box := []string{tl + h + a.Colors.Bold(titleText) + strings.Repeat(h, max(0, boxWidth-3-termui.Width(titleText))) + tr}
	for _, line := range content[:min(len(content), max(1, height-4))] {
		box = append(box, v+" "+termui.Fit(line, inner)+" "+v)
	}
	box = append(box, bl+strings.Repeat(h, boxWidth-2)+br)
	top := max(0, (height-len(box))/2)
	left := strings.Repeat(" ", max(0, (width-boxWidth)/2))
	for index := range lines {
		if row := index - top; row >= 0 && row < len(box) {
			lines[index] = termui.Fit(left+box[row], width)
		}
	}
	return lines
}
