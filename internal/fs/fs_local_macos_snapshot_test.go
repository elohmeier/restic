//go:build darwin

package fs

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	rtest "github.com/restic/restic/internal/test"
)

func TestMacOSSnapshotCreateLocalSnapshot(t *testing.T) {
	local := NewLocalMacOSSnapshot(func(item string, err error) {
		t.Fatalf("%s: %v", item, err)
	}, t.Logf)
	local.runCommand = func(name string, args ...string) (string, error) {
		rtest.Equals(t, "tmutil", name)
		rtest.Equals(t, []string{"localsnapshot"}, args)
		return "NOTE: local snapshots are considered purgeable and may be removed at any time by deleted(8).\nCreated local snapshot with date: 2026-05-01-193409\n", nil
	}

	date, err := local.createLocalSnapshot()
	rtest.OK(t, err)
	rtest.Equals(t, "2026-05-01-193409", date)
}

func TestMacOSSnapshotRelativePathInVolume(t *testing.T) {
	dir := t.TempDir()
	firmlinks := filepath.Join(dir, "firmlinks")
	rtest.OK(t, os.WriteFile(firmlinks, []byte(`
/Applications	Applications
/Users	Users
/private	private
/usr/local	usr/local
`), 0600))

	local := NewLocalMacOSSnapshot(func(item string, err error) {
		t.Fatalf("%s: %v", item, err)
	}, t.Logf)
	local.firmlinks, local.firmlinksErr = readMacOSFirmlinks(firmlinks)
	local.firmlinksOnce.Do(func() {})

	for _, test := range []struct {
		path       string
		mountPoint string
		want       string
	}{
		{"/System/Volumes/Data/Users/enno", "/System/Volumes/Data", "Users/enno"},
		{"/Users/enno", "/System/Volumes/Data", "Users/enno"},
		{"/Applications/App.app", "/System/Volumes/Data", "Applications/App.app"},
		{"/usr/local/bin/tool", "/System/Volumes/Data", "usr/local/bin/tool"},
		{"/var/folders", "/System/Volumes/Data", "private/var/folders"},
	} {
		t.Run(test.path, func(t *testing.T) {
			got, err := local.relativePathInVolume(test.path, test.mountPoint)
			rtest.OK(t, err)
			rtest.Equals(t, filepath.FromSlash(test.want), got)
		})
	}
}

func TestMacOSSnapshotPathAndCleanup(t *testing.T) {
	dir := t.TempDir()
	mountPath := filepath.Join(dir, "snapshot")
	var commands []string

	local := NewLocalMacOSSnapshot(func(item string, err error) {
		t.Fatalf("%s: %v", item, err)
	}, t.Logf)
	local.volumeInfo = func(path string) (macOSVolumeInfo, error) {
		return macOSVolumeInfo{
			fsType:     "apfs",
			mountPoint: "/System/Volumes/Data",
			device:     "/dev/disk1s1",
		}, nil
	}
	local.mkdirTemp = func() (string, error) {
		return mountPath, os.Mkdir(mountPath, 0700)
	}
	local.firmlinks = []macOSFirmlink{{source: "/Users", target: "Users"}}
	local.firmlinksOnce.Do(func() {})
	local.runCommand = func(name string, args ...string) (string, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		switch name {
		case "tmutil":
			if reflect.DeepEqual(args, []string{"localsnapshot"}) {
				return "Created local snapshot with date: 2026-05-01-193409\n", nil
			}
			return "", nil
		case "mount_apfs", "umount":
			return "", nil
		default:
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return "", nil
	}

	got := local.snapshotPath("/Users/enno/file")
	rtest.Equals(t, filepath.Join(mountPath, "Users", "enno", "file"), got)

	// The second lookup must reuse the existing mounted snapshot.
	got = local.snapshotPath("/Users/enno/other")
	rtest.Equals(t, filepath.Join(mountPath, "Users", "enno", "other"), got)

	local.DeleteSnapshots()

	rtest.Equals(t, []string{
		"tmutil localsnapshot",
		"mount_apfs -o rdonly,nobrowse -s com.apple.TimeMachine.2026-05-01-193409.local /System/Volumes/Data " + mountPath,
		"umount " + mountPath,
		"tmutil deletelocalsnapshots 2026-05-01-193409",
	}, commands)
}

func TestMacOSSnapshotNonAPFSPath(t *testing.T) {
	local := NewLocalMacOSSnapshot(func(item string, err error) {
		t.Fatalf("%s: %v", item, err)
	}, t.Logf)
	local.volumeInfo = func(path string) (macOSVolumeInfo, error) {
		return macOSVolumeInfo{fsType: "nfs"}, nil
	}

	rtest.Equals(t, "/tmp/file", local.snapshotPath("/tmp/file"))
}
