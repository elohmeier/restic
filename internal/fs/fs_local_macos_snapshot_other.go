//go:build !darwin

package fs

// LocalMacOSSnapshot is only available on macOS.
type LocalMacOSSnapshot struct {
	FS
}

// NewLocalMacOSSnapshot returns a local filesystem wrapper on non-macOS platforms.
func NewLocalMacOSSnapshot(_ ErrorHandler, _ MessageHandler) *LocalMacOSSnapshot {
	return &LocalMacOSSnapshot{FS: Local{}}
}

// DeleteSnapshots is a no-op on non-macOS platforms.
func (fs *LocalMacOSSnapshot) DeleteSnapshots() {}
