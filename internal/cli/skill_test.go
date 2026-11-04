package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	msecrets "github.com/k18k/msecrets"
)

var installed = []string{".claude/skills/msecrets/SKILL.md", ".agents/skills/msecrets/SKILL.md"}

// The SDK (@msecrets/ts-sdk) exports these functions.
var sdkFunctions = []string{"createClient", "injectEnv", "fromEnv", "fromFile", "fromKeychain", "fromCommand", "fromString", "parseSourceSpec", "autoSource", "MsecretsError", "isMsecretsError"}

func TestSkillFormat(t *testing.T) {
	frontmatter := regexp.MustCompile(`(?s)^---\n(.*?)\n---\n`).FindStringSubmatch(msecrets.Skill)
	if frontmatter == nil {
		t.Fatal("no frontmatter")
	}
	var keys []string
	fields := map[string]string{}
	for _, line := range strings.Split(frontmatter[1], "\n") {
		key, value, _ := strings.Cut(line, ":")
		keys = append(keys, key)
		fields[key] = strings.TrimSpace(value)
	}
	if !slices.Equal(keys, []string{"name", "description"}) || fields["name"] != "msecrets" {
		t.Fatal(keys, fields["name"])
	}
	if description := fields["description"]; len(description) <= 100 || len(description) > 1024 || strings.ContainsAny(description, "<>") {
		t.Fatal("description:", description)
	}
}

func TestSkillMentionsOnlyRealCommandsImportsAndCodes(t *testing.T) {
	names := map[string]bool{}
	for _, spec := range commands() {
		names[spec.name] = true
	}
	// Commands in inline code (`msecrets …`), and in code blocks at the start of a line or after a pipe.
	command := "msecrets ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?"
	used := regexp.MustCompile("`"+command).FindAllStringSubmatch(msecrets.Skill, -1)
	for _, block := range regexp.MustCompile("(?s)```[a-z]*\n(.*?)```").FindAllStringSubmatch(msecrets.Skill, -1) {
		used = append(used, regexp.MustCompile(`(?m)(?:^\s*|\| )`+command).FindAllStringSubmatch(block[1], -1)...)
	}
	if len(used) < 20 {
		t.Fatalf("only %d commands found", len(used))
	}
	for _, match := range used {
		if !names[match[1]+" "+match[2]] && !names[match[1]] {
			t.Errorf("SKILL.md uses %q, which is not a command", match[0])
		}
	}

	for _, match := range regexp.MustCompile(`import \{ ([A-Za-z, ]+) \} from "@msecrets/ts-sdk"`).FindAllStringSubmatch(msecrets.Skill, -1) {
		for _, name := range strings.Split(match[1], ", ") {
			if !slices.Contains(sdkFunctions, name) {
				t.Errorf("SKILL.md imports %s, which the SDK does not export", name)
			}
		}
	}

	var codes []string
	for _, match := range regexp.MustCompile("(?m)^\\| `([A-Z_]+)` ").FindAllStringSubmatch(msecrets.Skill, -1) {
		codes = append(codes, match[1])
	}
	if !slices.Equal(codes, []string{"NOT_FOUND", "IDENTITY_SOURCE", "ACCESS_DENIED", "SIGNATURE", "INVALID_FILE"}) {
		t.Fatal(codes)
	}
	errors := readFile(t, filepath.Join("..", "core", "errors.go"))
	for _, code := range codes {
		if !strings.Contains(errors, `ErrorCode = "`+code+`"`) {
			t.Errorf("%s is not an error code", code)
		}
	}

	for _, install := range []string{"npm install -g --allow-git=all github:k18k/msecrets#cli", "npm install --allow-git=root github:k18k/msecrets#ts-sdk"} {
		if !strings.Contains(msecrets.Skill, install) {
			t.Errorf("SKILL.md lacks %q", install)
		}
	}
}

func TestSkillPrint(t *testing.T) {
	r := newWorkspace(t).person("alice").run(t, []string{"skill", "--print"})
	ok(t, r)
	if r.stdout != msecrets.Skill {
		t.Fatal("printed skill differs")
	}
}

func TestSkillInstallsIntoTheGitRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	ws := newWorkspace(t)
	alice := ws.person("alice")
	gitInit := exec.Command("git", "init", "-q")
	gitInit.Dir, gitInit.Env = ws.root, alice.environ(nil)
	if output, err := gitInit.CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}

	first := alice.run(t, []string{"skill"})
	ok(t, first)
	for _, path := range installed {
		if readFile(t, filepath.Join(ws.root, path)) != msecrets.Skill {
			t.Fatal(path)
		}
	}
	expectMatch(t, first.stderr, `Installed .*\.claude[\\/]skills[\\/]msecrets[\\/]SKILL\.md`)
	expectMatch(t, first.stderr, `Commit these files`)

	writeFile(t, filepath.Join(ws.root, installed[0]), "old version")
	second := alice.run(t, []string{"skill"})
	ok(t, second)
	expectMatch(t, second.stderr, `Updated .*\.claude`)
	expectMatch(t, second.stderr, `Up to date: .*\.agents`)
	if readFile(t, filepath.Join(ws.root, installed[0])) != msecrets.Skill {
		t.Fatal("not updated")
	}
}

func TestSkillOutsideGitAndGlobal(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	// GIT_CEILING_DIRECTORIES keeps git from finding a repository above the temporary directory.
	env := runOptions{env: map[string]string{"GIT_CEILING_DIRECTORIES": ws.root}}
	ok(t, alice.run(t, []string{"skill"}, env))
	for _, path := range installed {
		if readFile(t, filepath.Join(ws.project, path)) != msecrets.Skill {
			t.Fatal(path)
		}
	}
	global := alice.run(t, []string{"skill", "--global"}, env)
	ok(t, global)
	expectMatch(t, global.stderr, `every project`)
	for _, path := range installed {
		if readFile(t, filepath.Join(ws.home, path)) != msecrets.Skill {
			t.Fatal(path)
		}
	}
}

func TestClaudeCodePlugin(t *testing.T) {
	var marketplace struct {
		Plugins []struct{ Name, Source string } `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(readFile(t, "../../.claude-plugin/marketplace.json")), &marketplace); err != nil {
		t.Fatal(err)
	}
	if len(marketplace.Plugins) != 1 || marketplace.Plugins[0].Name != "msecrets" || marketplace.Plugins[0].Source != "./" {
		t.Fatal(marketplace.Plugins)
	}
	var plugin struct{ Name, Version string }
	if err := json.Unmarshal([]byte(readFile(t, "../../.claude-plugin/plugin.json")), &plugin); err != nil {
		t.Fatal(err)
	}
	if plugin.Name != "msecrets" || plugin.Version != msecrets.Version {
		t.Fatalf("plugin %s %s, VERSION %s: bump the plugin version with VERSION", plugin.Name, plugin.Version, msecrets.Version)
	}
	// The plugin serves the skill from the repository root.
	if _, err := os.Stat("../../skills/msecrets/SKILL.md"); err != nil {
		t.Fatal(err)
	}
}
