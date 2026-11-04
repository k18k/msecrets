package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func emptyEnv() Host { return WithEnv(NativeHost(), map[string]string{}) }

func TestFindDocumentFile(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b", "c")
	check(t, os.MkdirAll(nested, 0o755))
	equal(t, must[string](t)(FindDocumentFile(NativeHost(), nested, DefaultFilename)), "")
	writeFile(t, filepath.Join(root, "a", DefaultFilename), "{}")
	equal(t, must[string](t)(FindDocumentFile(NativeHost(), nested, DefaultFilename)), filepath.Join(root, "a", DefaultFilename))
}

func TestResolveDocumentFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, DefaultFilename), "{}")
	equal(t, must[string](t)(ResolveDocumentFile(emptyEnv(), "", root)), filepath.Join(root, DefaultFilename))
	withFile := WithEnv(NativeHost(), map[string]string{"MSECRETS_FILE": "other.json"})
	equal(t, must[string](t)(ResolveDocumentFile(withFile, "", root)), filepath.Join(root, "other.json"))
	equal(t, must[string](t)(ResolveDocumentFile(withFile, "x.json", root)), filepath.Join(root, "x.json"))
	_, err := ResolveDocumentFile(emptyEnv(), "", t.TempDir())
	expectError(t, err, CodeNotFound, "msecrets init")
}

func TestLegacyFilePointsToMigration(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "src")
	writeFile(t, filepath.Join(root, ".env.ms.json"), `{"version":"3.0.0"}`)
	check(t, os.MkdirAll(nested, 0o755))
	_, err := ResolveDocumentFile(emptyEnv(), "", nested)
	expectError(t, err, CodeNotFound, "Coming from msecrets 3")
	if !strings.Contains(err.Error(), filepath.Join(root, ".env.ms.json")) {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, DefaultFilename), "{}")
	equal(t, must[string](t)(ResolveDocumentFile(emptyEnv(), "", nested)), filepath.Join(root, DefaultFilename))
}

func TestCreateAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	document, _ := sampleDocument(t)
	check(t, CreateDocumentFile(NativeHost(), path, document))
	equal(t, string(must[[]byte](t)(os.ReadFile(path))), SerializeDocument(document))
	expectError(t, CreateDocumentFile(NativeHost(), path, document), CodeConflict, "")
	equal(t, SerializeDocument(must[*Document](t)(ReadDocumentFile(NativeHost(), path))), SerializeDocument(document))
}

func TestAtomicUpdates(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultFilename)
	document, _ := sampleDocument(t)
	check(t, CreateDocumentFile(NativeHost(), path, document))
	before := must[os.FileInfo](t)(os.Stat(path)).ModTime()

	equal(t, must[int](t)(UpdateDocumentFile(NativeHost(), path, func(*Document) (int, error) { return 42, nil })), 42)
	equal(t, must[os.FileInfo](t)(os.Stat(path)).ModTime(), before)

	must[bool](t)(UpdateDocumentFile(NativeHost(), path, func(document *Document) (bool, error) {
		document.Secrets.Set("NEW", &SecretEntry{})
		return true, nil
	}))
	equal(t, must[*Document](t)(ReadDocumentFile(NativeHost(), path)).Secrets.Has("NEW"), true)
	entries := must[[]os.DirEntry](t)(os.ReadDir(directory))
	equal(t, len(entries), 1)
}

func TestFailedMutationsNeverReachTheDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	document, _ := sampleDocument(t)
	check(t, CreateDocumentFile(NativeHost(), path, document))
	original := string(must[[]byte](t)(os.ReadFile(path)))

	_, err := UpdateDocumentFile(NativeHost(), path, func(document *Document) (bool, error) {
		document.Secrets.Delete("DATABASE_URL")
		return false, fmt.Errorf("boom")
	})
	equal(t, err.Error(), "boom")
	_, err = UpdateDocumentFile(NativeHost(), path, func(document *Document) (bool, error) {
		development, _ := document.Environments.Get("development")
		development.Recipients = append(development.Recipients, "ghost")
		return true, nil
	})
	expectError(t, err, CodeInvalidFile, "")
	equal(t, string(must[[]byte](t)(os.ReadFile(path))), original)
	_, err = os.Stat(path + ".lock")
	equal(t, os.IsNotExist(err), true)
}

func TestConcurrentModification(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	document, _ := sampleDocument(t)
	check(t, CreateDocumentFile(NativeHost(), path, document))
	_, err := UpdateDocumentFile(NativeHost(), path, func(document *Document) (bool, error) {
		text := must[[]byte](t)(os.ReadFile(path))
		check(t, os.WriteFile(path, append(text, ' '), 0o644))
		document.Secrets.Delete("DEBUG")
		return true, nil
	})
	expectError(t, err, CodeConflict, "")
}

func TestWritersTakeTurns(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	document, _ := sampleDocument(t)
	check(t, CreateDocumentFile(NativeHost(), path, document))
	var wait sync.WaitGroup
	failures := make([]error, 6)
	for index := range failures {
		wait.Go(func() {
			cmd := exec.Command(os.Args[0])
			cmd.Env = append(os.Environ(), "MSECRETS_TEST_HELPER=update", "MSECRETS_TEST_FILE="+path, fmt.Sprintf("MSECRETS_TEST_OUTPUT=WRITER_%d", index))
			cmd.Stderr = os.Stderr
			failures[index] = cmd.Run()
		})
	}
	wait.Wait()
	for _, err := range failures {
		check(t, err)
	}
	var writers []string
	for _, name := range must[*Document](t)(ReadDocumentFile(NativeHost(), path)).Secrets.Keys() {
		if strings.HasPrefix(name, "WRITER_") {
			writers = append(writers, name)
		}
	}
	equal(t, strings.Join(writers, ","), "WRITER_0,WRITER_1,WRITER_2,WRITER_3,WRITER_4,WRITER_5")
	_, err := os.Stat(path + ".lock")
	equal(t, os.IsNotExist(err), true)
}

func TestCrashedWriterLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	document, _ := sampleDocument(t)
	check(t, CreateDocumentFile(NativeHost(), path, document))
	writeFile(t, path+".lock", "2147483646")
	must[bool](t)(UpdateDocumentFile(NativeHost(), path, func(document *Document) (bool, error) {
		document.Secrets.Set("AFTER_CRASH", &SecretEntry{})
		return true, nil
	}))
	equal(t, must[*Document](t)(ReadDocumentFile(NativeHost(), path)).Secrets.Has("AFTER_CRASH"), true)

	// An empty lock is taken over once it is old.
	writeFile(t, path+".lock", "")
	old := time.Now().Add(-time.Minute)
	check(t, os.Chtimes(path+".lock", old, old))
	must[bool](t)(UpdateDocumentFile(NativeHost(), path, func(*Document) (bool, error) { return true, nil }))
}

func TestMissingFile(t *testing.T) {
	_, err := ReadDocumentFile(NativeHost(), filepath.Join(t.TempDir(), "missing.json"))
	expectError(t, err, CodeNotFound, "")
}

func TestChooseEnvironment(t *testing.T) {
	document, _ := sampleDocument(t)
	choose := func(document *Document, h Host, explicit string) EnvironmentChoice {
		return must[EnvironmentChoice](t)(ChooseEnvironment(h, document, explicit))
	}
	equal(t, choose(document, emptyEnv(), "production"), EnvironmentChoice{"production", "explicit"})
	equal(t, choose(document, WithEnv(NativeHost(), map[string]string{"MSECRETS_ENV": "production"}), ""), EnvironmentChoice{"production", "variable"})
	equal(t, choose(document, emptyEnv(), ""), EnvironmentChoice{"development", "default"})

	single := copyDocument(t, document)
	single.Environments.Delete("development")
	equal(t, choose(single, emptyEnv(), ""), EnvironmentChoice{"production", "only"})

	single.Environments.Set("staging", &EnvironmentEntry{Recipients: []string{}})
	_, err := ChooseEnvironment(emptyEnv(), single, "")
	expectError(t, err, CodeUsage, "Choose an environment with --env or MSECRETS_ENV")

	_, err = ChooseEnvironment(emptyEnv(), document, "prodution")
	expectError(t, err, CodeNotFound, `did you mean "production"`)
}

func TestSuggest(t *testing.T) {
	equal(t, Suggest("DATABSE_URL", []string{"DATABASE_URL", "DEBUG"}), ` (did you mean "DATABASE_URL"?)`)
	equal(t, Suggest("ZZZ", []string{"DATABASE_URL"}), "")
}
