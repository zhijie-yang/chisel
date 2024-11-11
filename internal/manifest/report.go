package manifest

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/canonical/chisel/internal/fsutil"
	"github.com/canonical/chisel/internal/setup"
)

type ReportEntry struct {
	Path        string
	Mode        fs.FileMode
	SHA256      string
	Size        int
	Slices      map[*setup.Slice]bool
	Link        string
	FinalSHA256 string
	HardLinkId  int
}

// Report holds the information about files and directories created when slicing
// packages.
type Report struct {
	// Root is the filesystem path where the all reported content is based.
	Root string
	// Entries holds all reported content, indexed by their path.
	Entries        map[string]ReportEntry
	currHardLinkId int
}

// NewReport returns an empty report for content that will be based at the
// provided root path.
func NewReport(root string) (*Report, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("cannot use relative path for report root: %q", root)
	}
	root = filepath.Clean(root)
	if root != "/" {
		root = filepath.Clean(root) + "/"
	}
	report := &Report{
		Root:    root,
		Entries: make(map[string]ReportEntry),
	}
	return report, nil
}

func (r *Report) Add(slice *setup.Slice, fsEntry *fsutil.Entry) error {
	relPath, err := r.sanitizeAbsPath(fsEntry.Path, fsEntry.Mode.IsDir())
	if err != nil {
		return fmt.Errorf("cannot add path to report: %s", err)
	}

	// Handle the hard link group
	hardLinkId := 0
	sha256 := fsEntry.SHA256
	size := fsEntry.Size
	link := fsEntry.Link
	if link != "" {
		// Having the link target in root is a necessary but insufficient condition for a hardlink.
		if strings.HasPrefix(fsEntry.Link, r.Root) {
			relLinkPath, _ := r.sanitizeAbsPath(fsEntry.Link, false)
			// With this, a hardlink is found
			if entry, ok := r.Entries[relLinkPath]; ok {
				if entry.HardLinkId == 0 {
					r.currHardLinkId++
					entry.HardLinkId = r.currHardLinkId
					r.Entries[relLinkPath] = entry
				}
				hardLinkId = entry.HardLinkId
				if fsEntry.Mode.IsRegular() { // If the hardlink links to a regular file
					sha256 = entry.SHA256
					size = entry.Size
					link = ""
				} else { // If the hardlink links to a symlink
					link = entry.Link
				}
			}
		} // else, this is a symlink
	}

	if entry, ok := r.Entries[relPath]; ok {
		if fsEntry.Mode != entry.Mode {
			return fmt.Errorf("path %s reported twice with diverging mode: 0%03o != 0%03o", relPath, fsEntry.Mode, entry.Mode)
		} else if link != entry.Link {
			return fmt.Errorf("path %s reported twice with diverging link: %q != %q", relPath, link, entry.Link)
		} else if size != entry.Size {
			return fmt.Errorf("path %s reported twice with diverging size: %d != %d", relPath, size, entry.Size)
		} else if sha256 != entry.SHA256 {
			return fmt.Errorf("path %s reported twice with diverging hash: %q != %q", relPath, sha256, entry.SHA256)
		}
		entry.Slices[slice] = true
		r.Entries[relPath] = entry
	} else {
		r.Entries[relPath] = ReportEntry{
			Path:       relPath,
			Mode:       fsEntry.Mode,
			SHA256:     sha256,
			Size:       size,
			Slices:     map[*setup.Slice]bool{slice: true},
			Link:       link,
			HardLinkId: hardLinkId,
		}
	}
	return nil
}

// Mutate updates the FinalSHA256 and Size of an existing path entry.
func (r *Report) Mutate(fsEntry *fsutil.Entry) error {
	relPath, err := r.sanitizeAbsPath(fsEntry.Path, fsEntry.Mode.IsDir())
	if err != nil {
		return fmt.Errorf("cannot mutate path in report: %s", err)
	}

	entry, ok := r.Entries[relPath]
	if !ok {
		return fmt.Errorf("cannot mutate path in report: %s not previously added", relPath)
	}
	if entry.Mode.IsDir() {
		return fmt.Errorf("cannot mutate path in report: %s is a directory", relPath)
	}
	if entry.SHA256 == fsEntry.SHA256 {
		// Content has not changed, nothing to do.
		return nil
	}
	entry.FinalSHA256 = fsEntry.SHA256
	entry.Size = fsEntry.Size
	r.Entries[relPath] = entry
	return nil
}

func (r *Report) sanitizeAbsPath(path string, isDir bool) (relPath string, err error) {
	if !strings.HasPrefix(path, r.Root) {
		return "", fmt.Errorf("%s outside of root %s", path, r.Root)
	}
	relPath = filepath.Clean("/" + strings.TrimPrefix(path, r.Root))
	if isDir {
		relPath = relPath + "/"
	}
	return relPath, nil
}
