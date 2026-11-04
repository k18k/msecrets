// Package msecrets holds the release version and the agent skill, embedded
// from the repository root so the binary and the Claude Code plugin share them.
package msecrets

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var version string

// Version is the release version, e.g. "4.1.0".
var Version = strings.TrimSpace(version)

// Skill is skills/msecrets/SKILL.md, installed by `msecrets skill`.
//
//go:embed skills/msecrets/SKILL.md
var Skill string
