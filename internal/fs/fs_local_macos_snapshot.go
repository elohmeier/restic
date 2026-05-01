//go:build darwin

package fs

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/restic/restic/internal/errors"
)

type macOSSnapshotVolume struct {
	mountPoint string
	device     string
	snapshot   string
	mountPath  string
}

type macOSSnapshotCommandRunner func(name string, args ...string) (string, error)

// LocalMacOSSnapshot is a wrapper around the local filesystem which uses local
// Time Machine snapshots for APFS volumes.
type LocalMacOSSnapshot struct {
	FS

	mutex           sync.RWMutex
	volumes         map[string]*macOSSnapshotVolume
	failedSnapshots map[string]struct{}
	snapshotDate    string

	msgError   ErrorHandler
	msgMessage MessageHandler
	runCommand macOSSnapshotCommandRunner
	volumeInfo func(path string) (macOSVolumeInfo, error)
	mkdirTemp  func() (string, error)

	firmlinksOnce sync.Once
	firmlinks     []macOSFirmlink
	firmlinksErr  error
}

var _ FS = &LocalMacOSSnapshot{}

type macOSFirmlink struct {
	source string
	target string
}

// NewLocalMacOSSnapshot creates a new wrapper around the local filesystem using
// local Time Machine snapshots.
func NewLocalMacOSSnapshot(msgError ErrorHandler, msgMessage MessageHandler) *LocalMacOSSnapshot {
	return &LocalMacOSSnapshot{
		FS:              Local{},
		volumes:         make(map[string]*macOSSnapshotVolume),
		failedSnapshots: make(map[string]struct{}),
		msgError:        msgError,
		msgMessage:      msgMessage,
		runCommand:      runMacOSSnapshotCommand,
		volumeInfo:      macOSVolumeInfoForPath,
		mkdirTemp: func() (string, error) {
			return os.MkdirTemp("", "restic-macos-snapshot-")
		},
	}
}

func runMacOSSnapshotCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), errors.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// DeleteSnapshots unmounts and deletes all snapshots that were created automatically.
func (fs *LocalMacOSSnapshot) DeleteSnapshots() {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	for key, volume := range fs.volumes {
		if volume.mountPath == "" {
			continue
		}

		if _, err := fs.runCommand("umount", volume.mountPath); err != nil {
			fs.msgError(volume.mountPoint, errors.Errorf("failed to unmount APFS snapshot at %s: %s", volume.mountPath, err))
			continue
		}

		if err := os.Remove(volume.mountPath); err != nil {
			fs.msgError(volume.mountPoint, errors.Errorf("failed to remove APFS snapshot mountpoint %s: %s", volume.mountPath, err))
			continue
		}

		delete(fs.volumes, key)
	}

	if fs.snapshotDate != "" {
		if _, err := fs.runCommand("tmutil", "deletelocalsnapshots", fs.snapshotDate); err != nil {
			fs.msgError(fs.snapshotDate, errors.Errorf("failed to delete local Time Machine snapshot: %s", err))
		}
		fs.snapshotDate = ""
	}
}

// OpenFile wraps the OpenFile method of the underlying file system.
func (fs *LocalMacOSSnapshot) OpenFile(name string, flag int, metadataOnly bool) (File, error) {
	return fs.FS.OpenFile(fs.snapshotPath(name), flag, metadataOnly)
}

// Lstat wraps the Lstat method of the underlying file system.
func (fs *LocalMacOSSnapshot) Lstat(name string) (*ExtendedFileInfo, error) {
	return fs.FS.Lstat(fs.snapshotPath(name))
}

func (fs *LocalMacOSSnapshot) snapshotPath(path string) string {
	absPath, err := fs.Abs(path)
	if err != nil {
		fs.msgError(path, errors.Errorf("failed to determine absolute path: %s", err))
		return path
	}

	volume, rel, err := fs.snapshotVolumeAndRelativePath(absPath)
	if err != nil {
		fs.msgError(path, err)
		return path
	}
	if volume == nil {
		return path
	}

	return fs.Join(volume.mountPath, rel)
}

func (fs *LocalMacOSSnapshot) snapshotVolumeAndRelativePath(absPath string) (*macOSSnapshotVolume, string, error) {
	info, err := fs.volumeInfo(absPath)
	if err != nil {
		return nil, "", err
	}
	if info.fsType != "apfs" {
		return nil, "", nil
	}

	rel, err := fs.relativePathInVolume(absPath, info.mountPoint)
	if err != nil {
		return nil, "", err
	}

	volume := fs.ensureSnapshot(info)
	if volume == nil {
		return nil, "", nil
	}

	return volume, rel, nil
}

func (fs *LocalMacOSSnapshot) ensureSnapshot(info macOSVolumeInfo) *macOSSnapshotVolume {
	fs.mutex.RLock()
	volume, snapshotExists := fs.volumes[info.mountPoint]
	_, snapshotFailed := fs.failedSnapshots[info.mountPoint]
	if snapshotExists || snapshotFailed {
		fs.mutex.RUnlock()
		return volume
	}
	fs.mutex.RUnlock()

	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	if volume, ok := fs.volumes[info.mountPoint]; ok {
		return volume
	}
	if _, ok := fs.failedSnapshots[info.mountPoint]; ok {
		return nil
	}

	if fs.snapshotDate == "" {
		fs.msgMessage("creating local Time Machine snapshot\n")
		date, err := fs.createLocalSnapshot()
		if err != nil {
			fs.msgError(info.mountPoint, errors.Errorf("failed to create local Time Machine snapshot: %s", err))
			fs.failedSnapshots[info.mountPoint] = struct{}{}
			return nil
		}
		fs.snapshotDate = date
		fs.msgMessage("created local Time Machine snapshot %s\n", date)
	}

	snapshotName := "com.apple.TimeMachine." + fs.snapshotDate + ".local"
	mountPath, err := fs.mkdirTemp()
	if err != nil {
		fs.msgError(info.mountPoint, errors.Errorf("failed to create APFS snapshot mountpoint: %s", err))
		fs.failedSnapshots[info.mountPoint] = struct{}{}
		return nil
	}

	fs.msgMessage("mounting APFS snapshot %s for [%s]\n", snapshotName, info.mountPoint)
	if _, err := fs.runCommand("mount_apfs", "-o", "rdonly,nobrowse", "-s", snapshotName, info.mountPoint, mountPath); err != nil {
		_ = os.Remove(mountPath)
		fs.msgError(info.mountPoint, errors.Errorf("failed to mount APFS snapshot %s for [%s]: %s", snapshotName, info.mountPoint, err))
		fs.failedSnapshots[info.mountPoint] = struct{}{}
		return nil
	}

	volume = &macOSSnapshotVolume{
		mountPoint: info.mountPoint,
		device:     info.device,
		snapshot:   snapshotName,
		mountPath:  mountPath,
	}
	fs.volumes[info.mountPoint] = volume
	fs.msgMessage("successfully mounted APFS snapshot for [%s]\n", info.mountPoint)
	return volume
}

func (fs *LocalMacOSSnapshot) createLocalSnapshot() (string, error) {
	out, err := fs.runCommand("tmutil", "localsnapshot")
	if err != nil {
		return "", err
	}

	const prefix = "Created local snapshot with date: "
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			date := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if date != "" {
				return date, nil
			}
		}
	}

	return "", errors.Errorf("unable to determine local snapshot date from tmutil output: %s", strings.TrimSpace(out))
}

func (fs *LocalMacOSSnapshot) relativePathInVolume(absPath, mountPoint string) (string, error) {
	if rel, ok := fs.relativePathInVolumeForPath(absPath, mountPoint); ok {
		return rel, nil
	}

	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err == nil && resolvedPath != absPath {
		if rel, ok := fs.relativePathInVolumeForPath(resolvedPath, mountPoint); ok {
			return rel, nil
		}
	}

	return "", errors.Errorf("unable to map %s to APFS volume mounted at %s", absPath, mountPoint)
}

func (fs *LocalMacOSSnapshot) relativePathInVolumeForPath(absPath, mountPoint string) (string, bool) {
	if HasPathPrefix(mountPoint, absPath) {
		rel, err := filepath.Rel(mountPoint, absPath)
		return rel, err == nil
	}

	for _, firmlink := range fs.loadFirmlinks() {
		if !HasPathPrefix(firmlink.source, absPath) {
			continue
		}

		rel, err := filepath.Rel(firmlink.source, absPath)
		if err != nil {
			return "", false
		}
		return fs.Join(firmlink.target, rel), true
	}

	return "", false
}

func (fs *LocalMacOSSnapshot) loadFirmlinks() []macOSFirmlink {
	fs.firmlinksOnce.Do(func() {
		fs.firmlinks, fs.firmlinksErr = readMacOSFirmlinks("/usr/share/firmlinks")
		if fs.firmlinksErr != nil {
			fs.msgError("/usr/share/firmlinks", fs.firmlinksErr)
		}
	})

	return fs.firmlinks
}

func readMacOSFirmlinks(filename string) ([]macOSFirmlink, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var links []macOSFirmlink
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, errors.Errorf("invalid firmlink entry %q", line)
		}

		links = append(links, macOSFirmlink{
			source: filepath.Clean(fields[0]),
			target: filepath.Clean(fields[1]),
		})
	}

	sort.Slice(links, func(i, j int) bool {
		return len(links[i].source) > len(links[j].source)
	})

	return links, nil
}

type macOSVolumeInfo struct {
	fsType     string
	mountPoint string
	device     string
}

func macOSVolumeInfoForPath(path string) (macOSVolumeInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return macOSVolumeInfo{}, err
	}

	return macOSVolumeInfo{
		fsType:     int8String(stat.Fstypename[:]),
		mountPoint: int8String(stat.Mntonname[:]),
		device:     int8String(stat.Mntfromname[:]),
	}, nil
}

func int8String(data []int8) string {
	var b strings.Builder
	for _, c := range data {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}
