package core

import (
	"path/filepath"
	"regexp"
	"strings"
)

var cmdMeta = regexp.MustCompile(`([()\][%!^"` + "`" + `<>&|;, *?])`)

// quoteWindowsArgument quotes an argument for CreateProcess: backslashes double only before a quote or the end.
func quoteWindowsArgument(argument string) string {
	var b strings.Builder
	b.WriteByte('"')
	backslashes := 0
	for _, char := range argument {
		if char == '\\' {
			backslashes++
			continue
		}
		if char == '"' {
			backslashes = backslashes*2 + 1
		}
		b.WriteString(strings.Repeat(`\`, backslashes))
		b.WriteRune(char)
		backslashes = 0
	}
	b.WriteString(strings.Repeat(`\`, backslashes*2))
	b.WriteByte('"')
	return b.String()
}

func escapeCmdMeta(text string) string { return cmdMeta.ReplaceAllString(text, "^$1") }

var windowsSeparator = regexp.MustCompile(`[\\/]`)

func splitNonEmpty(text, separator string) []string {
	var parts []string
	for _, part := range strings.Split(text, separator) {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

// resolveWindowsCommand resolves a command like the Windows shell does (PATH and PATHEXT), or returns "".
func resolveWindowsCommand(h Host, command, cwd string) string {
	pathExt, ok := h.LookupEnv("PATHEXT")
	if !ok {
		pathExt = ".COM;.EXE;.BAT;.CMD"
	}
	extensions := splitNonEmpty(pathExt, ";")
	if filepath.Ext(command) != "" {
		extensions = []string{""}
	}
	directories := []string{""}
	if !isAbsolute(h, command) && !windowsSeparator.MatchString(command) {
		path, ok := h.LookupEnv("PATH")
		if !ok {
			path = getenv(h, "Path")
		}
		directories = append([]string{cwd}, splitNonEmpty(path, ";")...)
	}
	for _, directory := range directories {
		for _, extension := range extensions {
			candidate := resolvePath(h, cwd, filepath.Join(directory, command+extension))
			if info, err := h.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return candidate
			}
		}
	}
	return ""
}

// CommandPlan is how to start a command without a shell.
type CommandPlan struct {
	File string
	Args []string
	// Verbatim: pass Args unquoted (see [Command]).
	Verbatim bool
}

var batchFile = regexp.MustCompile(`(?i)\.(cmd|bat)$`)

// PlanCommand plans how to start argv without a shell. On Windows, commands
// resolve through PATH and PATHEXT, and .cmd/.bat shims (such as npm-installed
// CLIs) run through cmd.exe with every argument escaped.
func PlanCommand(h Host, argv []string, cwd string) (CommandPlan, error) {
	if len(argv) == 0 || argv[0] == "" {
		return CommandPlan{}, newError(CodeUsage, "No command given")
	}
	command, args := argv[0], argv[1:]
	if h.Platform() != "windows" {
		return CommandPlan{File: command, Args: args}, nil
	}

	resolved := resolveWindowsCommand(h, command, cwd)
	if resolved == "" {
		resolved = command
	}
	if !batchFile.MatchString(resolved) {
		return CommandPlan{File: resolved, Args: args}, nil
	}
	line := []string{escapeCmdMeta(resolved)}
	for _, argument := range args {
		// Batch files parse their arguments a second time.
		line = append(line, escapeCmdMeta(escapeCmdMeta(quoteWindowsArgument(argument))))
	}
	comSpec := getenv(h, "ComSpec")
	if comSpec == "" {
		comSpec = "cmd.exe"
	}
	return CommandPlan{File: comSpec, Args: []string{"/d", "/s", "/c", `"` + strings.Join(line, " ") + `"`}, Verbatim: true}, nil
}
