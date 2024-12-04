package testutil

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/canonical/chisel/internal/fsutil"
)

func TreeDump(dir string) map[string]string {
	result := make(map[string]string)
	pathsByInodes := make(map[uint64][]string)
	dirfs := os.DirFS(dir)
	err := fs.WalkDir(dirfs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk error: %w", err)
		}
		if path == "." {
			return nil
		}
		finfo, err := d.Info()
		if err != nil {
			return fmt.Errorf("cannot get stat info for %q: %w", path, err)
		}
		fperm := finfo.Mode() & fs.ModePerm
		ftype := finfo.Mode() & fs.ModeType
		if finfo.Mode()&fs.ModeSticky != 0 {
			fperm |= 01000
		}
		fpath := filepath.Join(dir, path)
		switch ftype {
		case fs.ModeDir:
			result["/"+path+"/"] = fmt.Sprintf("dir %#o", fperm)
		case fs.ModeSymlink:
			lpath, err := os.Readlink(fpath)
			if err != nil {
				return err
			}
			result["/"+path] = fmt.Sprintf("symlink %s", lpath)
		case 0: // Regular
			data, err := os.ReadFile(fpath)
			if err != nil {
				return fmt.Errorf("cannot read file: %w", err)
			}
			var entry string
			if len(data) == 0 {
				entry = fmt.Sprintf("file %#o empty", fperm)
			} else {
				sum := sha256.Sum256(data)
				entry = fmt.Sprintf("file %#o %.4x", fperm, sum)
			}
			result["/"+path] = entry
		default:
			return fmt.Errorf("unknown file type %d: %s", ftype, fpath)
		}

		stat, ok := finfo.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot get syscall stat info for %q", path)
		}
		inode := stat.Ino
		if ftype != fs.ModeDir {
			pathsByInodes[inode] = append(pathsByInodes[inode], "/"+path)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	// Append identifiers to paths who share an inode e.g. hard links.
	var inodes []uint64
	for inode, paths := range pathsByInodes {
		if len(paths) < 2 {
			continue
		}
		inodes = append(inodes, inode)
		// Keep the smallest path in front for easier comparison later.
		for i := 1; i < len(paths); i++ {
			if paths[i] < paths[0] {
				paths[0], paths[i] = paths[i], paths[0]
			}
		}
	}
	sort.Slice(inodes, func(i, j int) bool {
		return pathsByInodes[inodes[i]][0] < pathsByInodes[inodes[j]][0]
	})
	for i := 0; i < len(inodes); i++ {
		paths := pathsByInodes[inodes[i]]
		suff := fmt.Sprintf(" <%d>", i+1)
		for _, path := range paths {
			result[path] += suff
		}
	}
	return result
}

// TreeDumpEntry the file information in the same format as [testutil.TreeDump].
func TreeDumpEntry(entry *fsutil.Entry) string {
	fperm := entry.Mode.Perm()
	if entry.Mode&fs.ModeSticky != 0 {
		fperm |= 01000
	}
	switch entry.Mode.Type() {
	case fs.ModeDir:
		return fmt.Sprintf("dir %#o", fperm)
	case fs.ModeSymlink:
		return fmt.Sprintf("symlink %s", entry.Link)
	case 0:
		// Regular file.
		if entry.Size == 0 {
			return fmt.Sprintf("file %#o empty", entry.Mode.Perm())
		} else {
			return fmt.Sprintf("file %#o %s", fperm, entry.SHA256[:8])
		}
	default:
		panic(fmt.Errorf("unknown file type %d: %s", entry.Mode.Type(), entry.Path))
	}
}
