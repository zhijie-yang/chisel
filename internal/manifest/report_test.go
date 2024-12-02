package manifest_test

import (
	"io/fs"

	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/fsutil"
	"github.com/canonical/chisel/internal/manifest"
	"github.com/canonical/chisel/internal/setup"
)

var oneSlice = &setup.Slice{
	Package:   "base-files",
	Name:      "my-slice",
	Essential: nil,
	Contents:  nil,
	Scripts:   setup.SliceScripts{},
}

var otherSlice = &setup.Slice{
	Package:   "base-files",
	Name:      "other-slice",
	Essential: nil,
	Contents:  nil,
	Scripts:   setup.SliceScripts{},
}

var sampleDir = fsutil.Entry{
	Path: "/base/example-dir/",
	Mode: fs.ModeDir | 0654,
	Link: "",
}

var sampleFile = fsutil.Entry{
	Path:   "/base/example-file",
	Mode:   0777,
	SHA256: "example-file_hash",
	Size:   5678,
	Link:   "",
}

var sampleSymLink = fsutil.Entry{
	Path:   "/base/example-link",
	Mode:   fs.ModeSymlink | 0777,
	SHA256: "example-file_hash",
	Size:   5678,
	Link:   "/base/example-file",
}

var sampleHardLink = fsutil.Entry{
	Path:     "/base/example-hard-link",
	Mode:     sampleFile.Mode,
	Link:     "/base/example-file",
	HardLink: true,
}

var sampleHardLinkSym = fsutil.Entry{
	Path:     "/base/example-hard-link-sym",
	Mode:     fs.ModeSymlink | sampleFile.Mode,
	Link:     "/base/example-link",
	HardLink: true,
}

var sampleFileMutated = fsutil.Entry{
	Path:   sampleFile.Path,
	SHA256: sampleFile.SHA256 + "_changed",
	Size:   sampleFile.Size + 10,
}

type sliceAndEntry struct {
	entry fsutil.Entry
	slice *setup.Slice
}

var reportTests = []struct {
	summary string
	add     []sliceAndEntry
	mutate  []*fsutil.Entry
	// indexed by path.
	expected map[string]manifest.ReportEntry
	// error after adding the last [sliceAndEntry].
	err string
}{{
	summary: "Regular directory",
	add:     []sliceAndEntry{{entry: sampleDir, slice: oneSlice}},
	expected: map[string]manifest.ReportEntry{
		"/example-dir/": {
			Path:   "/example-dir/",
			Mode:   fs.ModeDir | 0654,
			Slices: map[*setup.Slice]bool{oneSlice: true},
			Link:   "",
		}},
}, {
	summary: "Regular directory added by several slices",
	add: []sliceAndEntry{
		{entry: sampleDir, slice: oneSlice},
		{entry: sampleDir, slice: otherSlice},
	},
	expected: map[string]manifest.ReportEntry{
		"/example-dir/": {
			Path:   "/example-dir/",
			Mode:   fs.ModeDir | 0654,
			Slices: map[*setup.Slice]bool{oneSlice: true, otherSlice: true},
			Link:   "",
		}},
}, {
	summary: "Regular file",
	add:     []sliceAndEntry{{entry: sampleFile, slice: oneSlice}},
	expected: map[string]manifest.ReportEntry{
		"/example-file": {
			Path:   "/example-file",
			Mode:   0777,
			SHA256: "example-file_hash",
			Size:   5678,
			Slices: map[*setup.Slice]bool{oneSlice: true},
			Link:   "",
		}},
}, {
	summary: "Regular file link",
	add:     []sliceAndEntry{{entry: sampleSymLink, slice: oneSlice}},
	expected: map[string]manifest.ReportEntry{
		"/example-link": {
			Path:   "/example-link",
			Mode:   fs.ModeSymlink | 0777,
			SHA256: "example-file_hash",
			Size:   5678,
			Slices: map[*setup.Slice]bool{oneSlice: true},
			Link:   "/base/example-file",
		}},
}, {
	summary: "Several entries",
	add: []sliceAndEntry{
		{entry: sampleDir, slice: oneSlice},
		{entry: sampleFile, slice: otherSlice},
	},
	expected: map[string]manifest.ReportEntry{
		"/example-dir/": {
			Path:   "/example-dir/",
			Mode:   fs.ModeDir | 0654,
			Slices: map[*setup.Slice]bool{oneSlice: true},
			Link:   "",
		},
		"/example-file": {
			Path:   "/example-file",
			Mode:   0777,
			SHA256: "example-file_hash",
			Size:   5678,
			Slices: map[*setup.Slice]bool{otherSlice: true},
			Link:   "",
		}},
}, {
	summary: "Same path, identical files",
	add: []sliceAndEntry{
		{entry: sampleFile, slice: oneSlice},
		{entry: sampleFile, slice: oneSlice},
	},
	expected: map[string]manifest.ReportEntry{
		"/example-file": {
			Path:   "/example-file",
			Mode:   0777,
			SHA256: "example-file_hash",
			Size:   5678,
			Slices: map[*setup.Slice]bool{oneSlice: true},
			Link:   "",
		}},
}, {
	summary: "Error for same path distinct mode",
	add: []sliceAndEntry{
		{entry: sampleFile, slice: oneSlice},
		{entry: fsutil.Entry{
			Path:   sampleFile.Path,
			Mode:   0,
			SHA256: sampleFile.SHA256,
			Size:   sampleFile.Size,
			Link:   sampleFile.Link,
		}, slice: oneSlice},
	},
	err: `path /example-file reported twice with diverging mode: 0000 != 0777`,
}, {
	summary: "Error for same path distinct hash",
	add: []sliceAndEntry{
		{entry: sampleFile, slice: oneSlice},
		{entry: fsutil.Entry{
			Path:   sampleFile.Path,
			Mode:   sampleFile.Mode,
			SHA256: "distinct hash",
			Size:   sampleFile.Size,
			Link:   sampleFile.Link,
		}, slice: oneSlice},
	},
	err: `path /example-file reported twice with diverging hash: "distinct hash" != "example-file_hash"`,
}, {
	summary: "Error for same path distinct size",
	add: []sliceAndEntry{
		{entry: sampleFile, slice: oneSlice},
		{entry: fsutil.Entry{
			Path:   sampleFile.Path,
			Mode:   sampleFile.Mode,
			SHA256: sampleFile.SHA256,
			Size:   0,
			Link:   sampleFile.Link,
		}, slice: oneSlice},
	},
	err: `path /example-file reported twice with diverging size: 0 != 5678`,
}, {
	summary: "Error for same path distinct link",
	add: []sliceAndEntry{
		{entry: sampleSymLink, slice: oneSlice},
		{entry: fsutil.Entry{
			Path:   sampleSymLink.Path,
			Mode:   sampleSymLink.Mode,
			SHA256: sampleSymLink.SHA256,
			Size:   sampleSymLink.Size,
			Link:   "distinct link",
		}, slice: oneSlice},
	},
	err: `path /example-link reported twice with diverging link: "distinct link" != "/base/example-file"`,
}, {
	summary: "Error for path outside root",
	add: []sliceAndEntry{
		{entry: fsutil.Entry{Path: "/file"}, slice: oneSlice},
	},
	err: `cannot add path to report: /file outside of root /base/`,
}, {
	summary: "Error for mutated path outside root",
	mutate:  []*fsutil.Entry{{Path: "/file"}},
	err:     `cannot mutate path in report: /file outside of root /base/`,
}, {
	summary: "File name has root prefix but without the directory slash",
	add: []sliceAndEntry{
		{entry: fsutil.Entry{Path: "/basefile"}, slice: oneSlice},
	},
	err: `cannot add path to report: /basefile outside of root /base/`,
}, {
	summary: "Add mutated regular file",
	add: []sliceAndEntry{
		{entry: sampleFile, slice: oneSlice},
		{entry: sampleDir, slice: oneSlice},
	},
	mutate: []*fsutil.Entry{&sampleFileMutated},
	expected: map[string]manifest.ReportEntry{
		"/example-dir/": {
			Path:   "/example-dir/",
			Mode:   fs.ModeDir | 0654,
			Slices: map[*setup.Slice]bool{oneSlice: true},
			Link:   "",
		},
		"/example-file": {
			Path:        "/example-file",
			Mode:        0777,
			SHA256:      "example-file_hash",
			Size:        5688,
			Slices:      map[*setup.Slice]bool{oneSlice: true},
			Link:        "",
			FinalSHA256: "example-file_hash_changed",
		}},
}, {
	summary: "Calling mutated with identical content to initial file",
	add: []sliceAndEntry{
		{entry: sampleFile, slice: oneSlice},
	},
	mutate: []*fsutil.Entry{&sampleFile},
	expected: map[string]manifest.ReportEntry{
		"/example-file": {
			Path:   "/example-file",
			Mode:   0777,
			SHA256: "example-file_hash",
			Size:   5678,
			Slices: map[*setup.Slice]bool{oneSlice: true},
			Link:   "",
			// FinalSHA256 is not updated.
			FinalSHA256: "",
		}},
}, {
	summary: "Mutated paths must refer to previously added entries",
	mutate:  []*fsutil.Entry{&sampleFileMutated},
	err:     `cannot mutate path in report: /example-file not previously added`,
}, {
	summary: "Cannot mutate directory",
	add:     []sliceAndEntry{{entry: sampleDir, slice: oneSlice}},
	mutate:  []*fsutil.Entry{&sampleDir},
	err:     `cannot mutate path in report: /example-dir/ is a directory`,
}, {
	summary: "Hard link to regular file",
	add: []sliceAndEntry{
		{entry: sampleFile, slice: oneSlice},
		{entry: sampleHardLink, slice: oneSlice}},
	expected: map[string]manifest.ReportEntry{
		"/example-file": {
			Path:       "/example-file",
			Mode:       0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{oneSlice: true},
			HardLinkID: 1,
		},
		"/example-hard-link": {
			Path:       "/example-hard-link",
			Mode:       0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{oneSlice: true},
			HardLinkID: 1,
		},
	},
}, {
	summary: "Hard link to symlink",
	add: []sliceAndEntry{
		{entry: sampleSymLink, slice: oneSlice},
		{entry: sampleHardLinkSym, slice: oneSlice}},
	expected: map[string]manifest.ReportEntry{
		"/example-link": {
			Path:       "/example-link",
			Mode:       fs.ModeSymlink | 0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{oneSlice: true},
			Link:       "/base/example-file",
			HardLinkID: 1,
		},
		"/example-hard-link-sym": {
			Path:       "/example-hard-link-sym",
			Mode:       fs.ModeSymlink | 0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{oneSlice: true},
			Link:       "/base/example-file",
			HardLinkID: 1,
		},
	},
}, {
	summary: "Multiple hard links groups",
	add: []sliceAndEntry{{
		entry: sampleFile,
		slice: oneSlice,
	}, {
		entry: sampleHardLink,
		slice: oneSlice,
	}, {
		entry: fsutil.Entry{
			Path:   "/base/another-file",
			Mode:   0777,
			SHA256: "another-file_hash",
			Size:   5678,
		},
		slice: otherSlice,
	}, {
		entry: fsutil.Entry{
			Path:     "/base/another-hard-link",
			Mode:     0777,
			Link:     "/base/another-file",
			HardLink: true,
		},
		slice: otherSlice,
	}},
	expected: map[string]manifest.ReportEntry{
		"/example-file": {
			Path:       "/example-file",
			Mode:       0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{oneSlice: true},
			HardLinkID: 1,
		},
		"/example-hard-link": {
			Path:       "/example-hard-link",
			Mode:       0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{oneSlice: true},
			HardLinkID: 1,
		},
		"/another-file": {
			Path:       "/another-file",
			Mode:       0777,
			SHA256:     "another-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{otherSlice: true},
			HardLinkID: 2,
		},
		"/another-hard-link": {
			Path:       "/another-hard-link",
			Mode:       0777,
			SHA256:     "another-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{otherSlice: true},
			HardLinkID: 2,
		},
	},
}, {
	summary: "Hard links to same file in different slices",
	add: []sliceAndEntry{{
		entry: sampleFile, slice: oneSlice,
	}, {
		entry: sampleHardLink, slice: oneSlice,
	}, {
		entry: fsutil.Entry{
			Path:     "/base/another-hard-link",
			Mode:     0777,
			Link:     "/base/example-file",
			HardLink: true,
		},
		slice: otherSlice,
	}},
	expected: map[string]manifest.ReportEntry{
		"/example-file": {
			Path:       "/example-file",
			Mode:       0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{oneSlice: true},
			HardLinkID: 1,
		},
		"/example-hard-link": {
			Path:       "/example-hard-link",
			Mode:       0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{oneSlice: true},
			HardLinkID: 1,
		},
		"/another-hard-link": {
			Path:       "/another-hard-link",
			Mode:       0777,
			SHA256:     "example-file_hash",
			Size:       5678,
			Slices:     map[*setup.Slice]bool{otherSlice: true},
			HardLinkID: 1,
		},
	},
}}

func (s *S) TestReport(c *C) {
	for _, test := range reportTests {
		var err error
		report, err := manifest.NewReport("/base/")
		c.Assert(err, IsNil)
		for _, si := range test.add {
			err = report.Add(si.slice, &si.entry)
		}
		for _, e := range test.mutate {
			err = report.Mutate(e)
		}
		if test.err != "" {
			c.Assert(err, ErrorMatches, test.err)
			continue
		}
		c.Assert(err, IsNil)
		c.Assert(report.Entries, DeepEquals, test.expected, Commentf(test.summary))
	}
}

func (s *S) TestRootRelativePath(c *C) {
	_, err := manifest.NewReport("../base/")
	c.Assert(err, ErrorMatches, `cannot use relative path for report root: "../base/"`)
}

func (s *S) TestRootOnlySlash(c *C) {
	report, err := manifest.NewReport("/")
	c.Assert(err, IsNil)
	c.Assert(report.Root, Equals, "/")
}
