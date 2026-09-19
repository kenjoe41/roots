package cert

import (
	"os"
	"os/user"
	"path/filepath"
	"sync"
)

// writeMu serializes the read-compare-write sequence in WriteLogState.
// runWorker's numWorkers goroutines checkpoint the same log's progress
// concurrently, in whatever order their batches happen to finish (not
// necessarily the order their ranges were assigned); without serializing
// the check, two goroutines could both read the same prior state, both
// decide their own index is the higher one, and the one that happens to
// write last wins regardless of which index was actually larger -
// silently regressing the persisted resume point and causing already
// processed entries to be re-fetched next run.
var writeMu sync.Mutex

// GetLogsDir returns the directory used to persist per-log-server resume
// state. Hidden under the home directory (`~/.certwatch/logs`) — resume
// state is internal tool bookkeeping, not something a user browses, so it
// belongs out of a plain `ls ~` listing like every other well-behaved
// tool's state dir. NOTE: hound's own internal/ctlogseed.DefaultLogsDir
// computes this exact same path independently in order to pre-seed roots'
// resume state; the two MUST stay byte-identical or hound seeds the wrong
// directory and every log silently does a full historical re-walk.
func GetLogsDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, ".certwatch", "logs"), nil
}

// CheckLogsFolder ensures the logs directory returned by GetLogsDir exists.
func CheckLogsFolder() error {
	dir, err := GetLogsDir()
	if err != nil {
		return err
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0700)
	}
	return nil
}

// WriteLogState persists the last processed index for a log server so a
// later run can resume from it. Never regresses an already-persisted,
// higher index - see writeMu's comment for why that matters when multiple
// workers checkpoint the same log concurrently.
func WriteLogState(logstate LogState) error {
	filename, err := logserverFilename(logstate)
	if err != nil {
		return err
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	var existing LogState
	if err := readJSONFile(filename, &existing); err == nil && existing.LogEndIndex >= logstate.LogEndIndex {
		return nil
	}
	return writeJSONFile(filename, logstate, 0600)
}

// ReadLogState reads back the last persisted state for a log server. If no
// state has been saved yet, it returns the zero-valued input state.
func ReadLogState(logstate LogState) (LogState, error) {
	filename, err := logserverFilename(logstate)
	if err != nil {
		return logstate, err
	}

	var saved LogState
	if err := readJSONFile(filename, &saved); err != nil {
		return logstate, err
	}
	return saved, nil
}
