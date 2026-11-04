package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	msecrets "github.com/k18k/msecrets"
	"github.com/k18k/msecrets/internal/core"
)

func git(c *Context, args ...string) (string, error) {
	command := exec.Command("git", args...)
	command.Dir = c.Cwd
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), message)
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(output)), nil
}

// readIfExists reads a text file; found is false when it does not exist.
func readIfExists(path string) (text string, found bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	return string(data), err == nil, err
}

// selfCommand is how git should invoke this binary: its resolved path, quoted for git's shell.
func selfCommand() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	return `"` + strings.ReplaceAll(executable, `\`, "/") + `"`, nil
}

var npxCache = regexp.MustCompile(`[\\/]_npx[\\/]`)

var gitSetupCommand = command{
	name:    "git setup",
	summary: "Configure readable diffs and a structural merge driver for this repository",
	run: func(c *Context, _ []string, _ flags) (int, error) {
		root, err := git(c, "rev-parse", "--show-toplevel")
		if err != nil {
			return 0, err
		}
		attributes := filepath.Join(root, ".gitattributes")
		line := core.DefaultFilename + " diff=msecrets merge=msecrets"
		current, _, err := readIfExists(attributes)
		if err != nil {
			return 0, err
		}
		lines := strings.Split(strings.ReplaceAll(current, "\r\n", "\n"), "\n")
		if !slices.Contains(lines, line) {
			prefix := ""
			if current != "" && !strings.HasSuffix(current, "\n") {
				prefix = "\n"
			}
			file, err := os.OpenFile(attributes, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return 0, err
			}
			_, err = file.WriteString(prefix + line + "\n")
			if err = errors.Join(err, file.Close()); err != nil {
				return 0, err
			}
		}

		self, err := selfCommand()
		if err != nil {
			return 0, err
		}
		for _, setting := range [][2]string{
			{"diff.msecrets.textconv", self + " git textconv"},
			{"merge.msecrets.name", "msecrets structural merge"},
			{"merge.msecrets.driver", self + " git merge-driver %O %A %B %P"},
		} {
			if _, err := git(c, "config", setting[0], setting[1]); err != nil {
				return 0, err
			}
		}
		c.Success("Configured .gitattributes (commit it) and this clone's git config")
		if npxCache.MatchString(self) {
			c.Warn("msecrets runs from the temporary npx cache, which npm may delete. Install it (`npm install -g --allow-git=all github:k18k/msecrets#cli`) and run `msecrets git setup` again.")
		}
		c.Note(c.Err.Dim("Every clone runs `msecrets git setup` once; git config is not shared through the repository."))
		return 0, nil
	},
}

var gitTextconvCommand = command{
	name:    "git textconv",
	args:    "<FILE>",
	summary: "Render a secrets file readably (used by git diff)",
	run: func(c *Context, args []string, _ flags) (int, error) {
		if err := requireArgs(args, 1, "git textconv <FILE>"); err != nil {
			return 0, err
		}
		data, err := os.ReadFile(resolve(c, args[0]))
		if err != nil {
			return 0, err
		}
		_, err = fmt.Fprint(c.Stdout, renderForDiff(string(data)))
		return 0, err
	},
}

var gitMergeDriverCommand = command{
	name:    "git merge-driver",
	args:    "<BASE> <OURS> <THEIRS> [PATH]",
	summary: "Three-way structural merge (used by git merge)",
	run: func(c *Context, args []string, _ flags) (int, error) {
		if err := requireArgs(args, 3, "git merge-driver <BASE> <OURS> <THEIRS> [PATH]"); err != nil {
			return 0, err
		}
		path := core.DefaultFilename
		if len(args) > 3 {
			path = args[3]
		}
		var texts [3]string
		for index := range texts {
			data, err := os.ReadFile(resolve(c, args[index]))
			if err != nil {
				return 0, err
			}
			texts[index] = string(data)
		}
		text, conflicts := mergeDocuments(texts[0], texts[1], texts[2])
		if err := os.WriteFile(resolve(c, args[1]), []byte(text), 0o644); err != nil {
			return 0, err
		}
		if len(conflicts) > 0 {
			c.Note(fmt.Sprintf("msecrets: conflicting changes in %s (kept your side):\n  %s\nResolve them with msecrets commands, then `git add %s`.", path, strings.Join(conflicts, "\n  "), path))
			return 1, nil
		}
		return 0, nil
	},
}

// Claude Code reads .claude/skills; Codex, Cursor, GitHub Copilot, Gemini CLI, and others read .agents/skills.
var skillDirectories = []string{".claude/skills", ".agents/skills"}

var skillCommand = command{
	name:     "skill",
	summary:  "Install the msecrets skill for AI coding agents (Claude Code, Codex, Cursor, Copilot, …)",
	examples: []string{"msecrets skill            # this repository", "msecrets skill --global   # every project"},
	options: []option{
		{name: "global", description: "Install for your user account instead of this project"},
		{name: "print", description: "Print the skill instead of installing it"},
	},
	run: func(c *Context, _ []string, f flags) (int, error) {
		content := msecrets.Skill
		if f.Bool("print") {
			_, err := fmt.Fprint(c.Stdout, content)
			return 0, err
		}
		global := f.Bool("global")
		var root string
		if global {
			root = firstNonEmpty(c.getenv("HOME"), c.getenv("USERPROFILE"))
			if root == "" {
				home, err := c.Host.HomeDir()
				if err != nil {
					return 0, err
				}
				root = home
			}
		} else if top, err := git(c, "rev-parse", "--show-toplevel"); err == nil {
			root = top
		} else {
			// Not a git repository (or no git): the working directory is the project.
			root = c.Cwd
		}
		for _, directory := range skillDirectories {
			path := filepath.Join(root, filepath.FromSlash(directory), "msecrets", "SKILL.md")
			current, found, err := readIfExists(path)
			if err != nil {
				return 0, err
			}
			if found && current == content {
				c.Note("Up to date: " + c.DisplayPath(path))
				continue
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return 0, err
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return 0, err
			}
			verb := "Installed"
			if found {
				verb = "Updated"
			}
			c.Success(verb + " " + c.DisplayPath(path))
		}
		if global {
			c.Note(c.Err.Dim("Agents now know msecrets in every project. Run `msecrets skill --global` again after upgrading."))
		} else {
			c.Note(c.Err.Dim("Commit these files so every teammate's agent knows msecrets. Run `msecrets skill` again after upgrading."))
		}
		return 0, nil
	},
}
