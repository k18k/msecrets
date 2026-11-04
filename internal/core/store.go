package core

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// legacyFilename is the msecrets 2 and 3 file name, recognized only to point to the migration guide.
const legacyFilename = ".env.ms.json"

var windowsAbsolute = regexp.MustCompile(`^(?:[A-Za-z]:)?[\\/]`)

// isAbsolute also recognizes Windows paths when core runs on a POSIX-like GOOS (js/wasm) on Windows.
func isAbsolute(h Host, path string) bool {
	return filepath.IsAbs(path) || (h.Platform() == "windows" && windowsAbsolute.MatchString(path))
}

// resolvePath resolves path against cwd, like Node.js path.resolve(cwd, path).
func resolvePath(h Host, cwd, path string) string {
	if isAbsolute(h, path) {
		if filepath.VolumeName(path) == "" {
			path = filepath.VolumeName(cwd) + path // \tmp on Windows is on the drive of cwd
		}
		return filepath.Clean(path)
	}
	return filepath.Join(cwd, path)
}

func workingDirectory(h Host, cwd string) (string, error) {
	if cwd != "" {
		return cwd, nil
	}
	return h.Getwd()
}

// FindDocumentFile finds filename in start ("" for the working directory) or the
// closest parent directory. It returns "" if there is none.
func FindDocumentFile(h Host, start, filename string) (string, error) {
	wd, err := h.Getwd()
	if err != nil {
		return "", err
	}
	for directory := resolvePath(h, wd, start); ; directory = filepath.Dir(directory) {
		candidate := filepath.Join(directory, filename)
		info, err := h.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if filepath.Dir(directory) == directory {
			return "", nil
		}
	}
}

// ResolveDocumentFile resolves the secrets file: the explicit path, then
// MSECRETS_FILE, then an upward search for msecrets.json from cwd ("" for the working directory).
func ResolveDocumentFile(h Host, explicit, cwd string) (string, error) {
	cwd, err := workingDirectory(h, cwd)
	if err != nil {
		return "", err
	}
	if explicit == "" {
		explicit = getenv(h, "MSECRETS_FILE")
	}
	if explicit != "" {
		return resolvePath(h, cwd, explicit), nil
	}

	found, err := FindDocumentFile(h, cwd, DefaultFilename)
	if err != nil || found != "" {
		return found, err
	}
	legacy, err := FindDocumentFile(h, cwd, legacyFilename)
	if err != nil {
		return "", err
	}
	if legacy != "" {
		return "", newError(CodeNotFound, "No %s found, but there is %s, the msecrets 3 file. To migrate, see \"Coming from msecrets 3\" at https://k18k.github.io/msecrets/file-format/", DefaultFilename, legacy)
	}
	return "", newError(CodeNotFound, "No %s found in %s or any parent directory. Create one with `msecrets init`, or point to it with --file or MSECRETS_FILE", DefaultFilename, cwd)
}

func readText(h Host, path string) ([]byte, error) {
	data, err := h.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, wrapError(CodeNotFound, err, "Secrets file not found: %s. Create it with `msecrets init`", path)
	}
	return data, err
}

// ReadDocumentFile reads and validates a secrets file.
func ReadDocumentFile(h Host, path string) (*Document, error) {
	data, err := readText(h, path)
	if err != nil {
		return nil, err
	}
	return ParseDocumentText(string(data), path)
}

// atomicReplace replaces a file through a temporary file and an atomic rename.
func atomicReplace(h Host, path string, data []byte) error {
	temporary := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.%d.%s.tmp", filepath.Base(path), h.Pid(), randomHex(6)))
	if err := h.CreateFile(temporary, data); err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		err := h.Rename(temporary, path)
		if err == nil {
			return nil
		}
		// Windows refuses to replace files that another process (an editor, an indexer) holds open for a moment.
		if h.Platform() != "windows" || attempt == 10 || errors.Is(err, fs.ErrNotExist) {
			return errors.Join(err, h.Remove(temporary))
		}
		h.Sleep(time.Duration(50*attempt) * time.Millisecond)
	}
}

// serializeChecked serializes and re-validates a document.
func serializeChecked(path string, document *Document) (string, error) {
	text := SerializeDocument(document)
	if _, err := ParseDocumentText(text, "the updated "+path); err != nil {
		return "", err
	}
	return text, nil
}

// CreateDocumentFile creates a new secrets file, failing with CONFLICT if one already exists.
func CreateDocumentFile(h Host, path string, document *Document) error {
	text, err := serializeChecked(path, document)
	if err != nil {
		return err
	}
	if err := h.CreateFile(path, []byte(text)); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return wrapError(CodeConflict, err, "%s already exists", path)
		}
		return err
	}
	return nil
}

const lockTimeout = 30 * time.Second

// staleLock reports whether a lock file belongs to a process that no longer exists (a crashed writer).
func staleLock(h Host, lock string) (bool, error) {
	text, err := h.ReadFile(lock)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil // Released meanwhile: try again.
	}
	if err != nil {
		return false, err
	}
	owner, err := strconv.Atoi(strings.TrimSpace(string(text)))
	if err != nil || owner <= 0 {
		// Empty while its owner writes it, or garbage: stale only once it is old.
		info, err := h.Stat(lock)
		if err != nil {
			return false, nil
		}
		return time.Since(info.ModTime()) > 5*time.Second, nil
	}
	return !h.ProcessExists(owner), nil
}

// withLock runs action while holding "<path>.lock", so writers on this machine take turns.
func withLock[T any](h Host, path string, action func() (T, error)) (T, error) {
	var zero T
	lock := path + ".lock"
	deadline := time.Now().Add(lockTimeout)
	for {
		err := h.CreateFile(lock, []byte(strconv.Itoa(h.Pid())))
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return zero, err
		}
		stale, err := staleLock(h, lock)
		switch {
		case err != nil:
			return zero, err
		case stale:
			if err := h.Remove(lock); err != nil {
				return zero, err
			}
		case time.Now().After(deadline):
			return zero, newError(CodeConflict, "%s is locked by another msecrets process. If none is running, delete %s", path, lock)
		default:
			h.Sleep(20 * time.Millisecond)
		}
	}
	result, err := action()
	return result, errors.Join(err, h.Remove(lock))
}

// UpdateDocumentFile is a read-modify-write of the secrets file. The mutation
// runs on a fresh copy; if it fails, nothing is written. msecrets processes
// take turns through a lock file; changes by anything else (an editor, git)
// during the operation are detected (CONFLICT).
func UpdateDocumentFile[T any](h Host, path string, mutate func(*Document) (T, error)) (T, error) {
	return withLock(h, path, func() (T, error) {
		var zero T
		before, err := readText(h, path)
		if err != nil {
			return zero, err
		}
		document, err := ParseDocumentText(string(before), path)
		if err != nil {
			return zero, err
		}
		result, err := mutate(document)
		if err != nil {
			return zero, err
		}
		text, err := serializeChecked(path, document)
		if err != nil {
			return zero, err
		}
		if text == string(before) {
			return result, nil
		}
		current, err := readText(h, path)
		if err != nil {
			return zero, err
		}
		if !bytes.Equal(current, before) {
			return zero, newError(CodeConflict, "%s changed on disk during the operation; run it again", path)
		}
		return result, atomicReplace(h, path, []byte(text))
	})
}
