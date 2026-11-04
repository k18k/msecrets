package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/k18k/msecrets/internal/core"
)

var initCommand = command{
	name:    "init",
	summary: "Create msecrets.json with you as its first recipient",
	examples: []string{
		"msecrets init",
		"msecrets init --env development,staging,production",
		"msecrets init --store file --passphrase   # an encrypted identity file instead of the OS keychain",
	},
	options: []option{optName, optStore, optPQ, optPassphrase},
	run: func(c *Context, _ []string, f flags) (int, error) {
		path := c.targetPath()
		if _, err := os.Stat(path); err == nil {
			return 0, coreError(core.CodeConflict, "%s already exists. To add yourself to it, run `msecrets join`", c.DisplayPath(path))
		} else if !errors.Is(err, fs.ErrNotExist) {
			return 0, err
		}
		environments := f.List("env")
		if len(environments) == 0 {
			environments = []string{"development", "production"}
		}
		for _, name := range environments {
			if err := core.RequireName(core.EnvironmentName, name); err != nil {
				return 0, err
			}
		}
		name := f.String("name")
		if name == "" {
			name = defaultRecipientName(c.Cwd)
		}
		if err := core.RequireName(core.RecipientName, name); err != nil {
			return 0, err
		}
		store, err := parseStoreTarget(f.String("store"))
		if err != nil {
			return 0, err
		}
		identity, err := ensureIdentity(c, store, f.Bool("pq"), f.Bool("passphrase"))
		if err != nil {
			return 0, err
		}

		document := core.CreateDocument()
		if _, err := core.AddRecipient(document, name, identity.PublicKey.Token, ""); err != nil {
			return 0, err
		}
		for _, environment := range environments {
			if err := core.AddEnvironment(document, environment, []string{name}); err != nil {
				return 0, err
			}
		}
		if err := core.CreateDocumentFile(c.Host, path, document); err != nil {
			return 0, err
		}

		display := c.DisplayPath(path)
		c.Success(fmt.Sprintf("Created %s (%s); you are recipient \"%s\"", display, strings.Join(environments, ", "), name))
		next := func(command, comment string) string {
			return fmt.Sprintf("  %-37s%s", command, c.Err.Dim("# "+comment))
		}
		c.Note(strings.Join([]string{"", "Next:",
			next("msecrets set DATABASE_URL", "add a secret (prompts for the value)"),
			next("msecrets run -- npm start", "run anything with the secrets as env vars"),
			next("msecrets git setup", "readable diffs and conflict-free merges"),
			next("git add "+display, "the file is safe to commit"),
		}, "\n"))
		return 0, nil
	},
}

var joinCommand = command{
	name:     "join",
	summary:  "Add yourself as a recipient of an existing secrets file",
	examples: []string{"msecrets join", "msecrets join --env development   # ask for access to development right away"},
	options:  []option{optName, optStore, optPQ, optPassphrase},
	run: func(c *Context, _ []string, f flags) (int, error) {
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		store, err := parseStoreTarget(f.String("store"))
		if err != nil {
			return 0, err
		}
		identity, err := ensureIdentity(c, store, f.Bool("pq"), f.Bool("passphrase"))
		if err != nil {
			return 0, err
		}
		existing, err := core.Members(document, []*core.Identity{identity})
		if err != nil {
			return 0, err
		}
		path, _ := c.Path()
		if len(existing) > 0 {
			c.Success(fmt.Sprintf("You are already recipient \"%s\" of %s", existing[0].Name, c.DisplayPath(path)))
			return 0, nil
		}

		name := f.String("name")
		if name == "" {
			name = defaultRecipientName(c.Cwd)
		}
		if err := core.RequireName(core.RecipientName, name); err != nil {
			return 0, err
		}
		environments := f.List("env")
		if _, err := update(c, func(current *core.Document) (any, error) {
			if _, err := core.AddRecipient(current, name, identity.PublicKey.Token, ""); err != nil {
				return nil, err
			}
			for _, environment := range environments {
				entry, err := core.RequireEnvironment(current, environment)
				if err != nil {
					return nil, err
				}
				entry.Recipients = append(entry.Recipients, name)
			}
			return nil, nil
		}); err != nil {
			return 0, err
		}

		if len(environments) > 0 {
			c.Success(fmt.Sprintf("Added you as recipient \"%s\" of %s", name, strings.Join(environments, ", ")))
			c.Note("Commit and push this change. Once it is reviewed, a member runs `msecrets sync` to re-encrypt the values for you.")
		} else {
			c.Success(fmt.Sprintf("Added you as recipient \"%s\"", name))
			c.Note(fmt.Sprintf("Commit and push this change, then ask a member to run `msecrets grant %s <environment>`.", name))
		}
		return 0, nil
	},
}

var whoamiCommand = command{
	name:    "whoami",
	summary: "Show your identities and what they can access",
	run: func(c *Context, _ []string, _ flags) (int, error) {
		loaded, err := c.LoadedIdentities()
		if err != nil {
			return 0, err
		}
		if len(loaded) == 0 {
			c.Print("No identity found. Create one with `msecrets identity new` (or `msecrets init` in a new project).")
			return 1, nil
		}
		document, err := c.Document()
		if err != nil && !core.IsError(err, core.CodeNotFound) {
			return 0, err
		}
		for _, entry := range loaded {
			key := entry.Identity.PublicKey
			c.Print(c.Out.Bold(string(key.Kind)) + " " + c.Out.Dim("from "+entry.Source))
			c.Print("  " + key.Token)
			if document == nil {
				continue
			}
			members, err := core.Members(document, []*core.Identity{entry.Identity})
			if err != nil {
				return 0, err
			}
			if len(members) == 0 {
				c.Print("  " + c.Out.Yellow("not a recipient of this file") + " " + c.Out.Dim("(run `msecrets join`)"))
				continue
			}
			name := members[0].Name
			recipientKey, err := core.RecipientKey(document, name)
			if err != nil {
				return 0, err
			}
			mode := "read"
			if recipientKey.SigningKey != nil {
				mode = "read/write"
			}
			var access []string
			for _, environment := range environmentsOf(document, name) {
				access = append(access, fmt.Sprintf("%s (%s)", environment, mode))
			}
			list := strings.Join(access, ", ")
			if list == "" {
				list = c.Out.Yellow("no environments")
			}
			c.Print(fmt.Sprintf("  recipient %s: %s", c.Out.Cyan(name), list))
		}
		return 0, nil
	},
}

var identityNewCommand = command{
	name:    "identity new",
	summary: "Generate a new identity and store it",
	examples: []string{
		"msecrets identity new                    # stored in the OS keychain",
		"msecrets identity new --store print      # print it, to keep it in a password manager",
		"msecrets identity new --account work",
	},
	options: []option{optStore, optPQ, optPassphrase,
		{name: "account", takesValue: true, placeholder: "NAME", description: "Keychain account / file name to use (default: default)"}},
	run: func(c *Context, _ []string, f flags) (int, error) {
		store, err := parseStoreTarget(f.String("store"))
		if err != nil {
			return 0, err
		}
		identity, err := core.GenerateIdentity(f.Bool("pq"))
		if err != nil {
			return 0, err
		}
		spec, err := storeIdentity(c, identity, store, f.String("account"), f.Bool("passphrase"))
		if err != nil {
			return 0, err
		}
		if spec == "" {
			c.Note(c.Err.Yellow("Store the identity printed above in your password manager, then run `msecrets identity use <source>`"))
			c.Note("Public key: " + identity.PublicKey.Token)
			return 0, nil
		}
		configPath, err := addIdentitySource(c, spec)
		if err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Stored the identity in %s; registered in %s", spec, configPath))
		c.Print(identity.PublicKey.Token)
		return 0, nil
	},
}

var identityShowCommand = command{
	name:    "identity show",
	summary: "Print the public keys of your identities",
	run: func(c *Context, _ []string, _ flags) (int, error) {
		identities, err := c.RequireIdentities()
		for _, identity := range identities {
			c.Print(identity.PublicKey.Token)
		}
		return 0, err
	},
}

var identityExportCommand = command{
	name:     "identity export",
	summary:  "Print your identities (private keys), e.g. to move them to a password manager",
	examples: []string{"msecrets identity export | op document create - --title msecrets"},
	options:  []option{optYes},
	run: func(c *Context, _ []string, f flags) (int, error) {
		identities, err := c.RequireIdentities()
		if err != nil {
			return 0, err
		}
		if c.StdoutTTY {
			if err := c.confirmDanger(f.Bool("yes"), "This prints your private key on the screen. Continue?"); err != nil {
				return 0, err
			}
		}
		for _, identity := range identities {
			fmt.Fprint(c.Stdout, core.FormatIdentityFile(identity, ""))
		}
		return 0, nil
	},
}

var identityUseCommand = command{
	name:    "identity use",
	args:    "<source>",
	summary: "Load your identity from a source (op://…, bw:…, pass:…, keychain:…, file:…, cmd:…)",
	examples: []string{
		"msecrets identity use op://Private/msecrets/identity",
		"msecrets identity use keychain:work",
		"msecrets identity use file:~/.ssh/id_ed25519",
	},
	run: func(c *Context, args []string, _ flags) (int, error) {
		if err := requireArgs(args, 1, "identity use <source>"); err != nil {
			return 0, err
		}
		source := args[0]
		probe := *c
		probe.Options = GlobalOptions{Identity: []string{source}}
		probe.loaded = false
		loaded, err := probe.LoadedIdentities()
		if err != nil {
			return 0, err
		}
		if len(loaded) == 0 {
			return 0, coreError(core.CodeIdentitySource, "%s did not yield any identity", source)
		}
		// The config is shared by every directory: store file paths absolute.
		configPath, err := addIdentitySource(c, core.AbsoluteSourceSpec(c.Host, source, c.Cwd))
		if err != nil {
			return 0, err
		}
		noun := "identities"
		if len(loaded) == 1 {
			noun = "identity"
		}
		c.Success(fmt.Sprintf("Using %s (%d %s); saved in %s", source, len(loaded), noun, configPath))
		for _, entry := range loaded {
			c.Print(entry.Identity.PublicKey.Token)
		}
		return 0, nil
	},
}
