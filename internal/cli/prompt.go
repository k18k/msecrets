package cli

import (
	"errors"
	"regexp"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/k18k/msecrets/internal/core"
)

// errCancelled: the user pressed ctrl-c or ctrl-d at a prompt (exit code 130).
var errCancelled = errors.New("Cancelled")

type promptModel struct {
	input     textinput.Model
	done      bool
	cancelled bool
}

func (m promptModel) Init() tea.Cmd { return nil }

func (m promptModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.Keystroke() {
		case "enter", "ctrl+j":
			m.done = true
			m.input.Blur()
			return m, tea.Quit
		case "ctrl+c", "ctrl+d":
			m.cancelled = true
			m.input.Blur()
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m promptModel) View() tea.View {
	if m.done || m.cancelled {
		// The final frame stays on screen: the question, and the answer unless it is hidden.
		return tea.NewView(m.input.Prompt + m.answer() + "\n")
	}
	return tea.NewView(m.input.View())
}

func (m promptModel) answer() string {
	if m.input.EchoMode == textinput.EchoNone {
		return ""
	}
	return m.input.Value()
}

// Ask asks a question on the terminal (stderr). Hidden answers are not echoed.
func (c *Context) Ask(question string, hidden bool) (string, error) {
	if !c.StdinTTY {
		return "", usageError("Cannot ask \"%s\" without a terminal", strings.TrimSpace(question))
	}
	input := textinput.New()
	input.Prompt = question
	input.CharLimit = 0
	if hidden {
		input.EchoMode = textinput.EchoNone
	}
	input.Focus()
	result, err := tea.NewProgram(promptModel{input: input}, tea.WithInput(c.Stdin), tea.WithOutput(c.Stderr)).Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return "", errCancelled
	}
	if err != nil {
		return "", err
	}
	model := result.(promptModel)
	if model.cancelled {
		return "", errCancelled
	}
	return model.input.Value(), nil
}

var yes = regexp.MustCompile(`(?i)^y(es)?$`)

// Confirm asks a yes/no question; the default is no.
func (c *Context) Confirm(question string) (bool, error) {
	answer, err := c.Ask(question+" [y/N] ", false)
	return yes.MatchString(strings.TrimSpace(answer)), err
}

// confirmDanger asks before a destructive change, unless --yes; without a terminal it requires --yes.
func (c *Context) confirmDanger(assumeYes bool, question string) error {
	if assumeYes {
		return nil
	}
	if !c.StdinTTY {
		return usageError("%s Pass --yes to confirm", question)
	}
	confirmed, err := c.Confirm(question)
	if err != nil {
		return err
	}
	if !confirmed {
		return &core.Error{Code: core.CodeUsage, Message: "Aborted"}
	}
	return nil
}
