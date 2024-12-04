package testutil_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/canonical/chisel/internal/testutil"
)

const (
	typeDir = "dir"
	typeReg = "regular"
	typeLnk = "symlink"
	typeHlk = "hardlink"
)

type dirEntry struct {
	kind   string
	path   string
	data   string
	mode   uint64
	target string
}

type treeDumpTest struct {
	summary  string
	files    []dirEntry
	expected map[string]string
}

var treeDumpTests = []treeDumpTest{{
	summary: "All kinds of path",
	files: []dirEntry{{
		kind: typeDir, path: "./dir", mode: 0755,
	}, {
		kind: typeReg, path: "./dir/file1", data: "foo", mode: 0644,
	}, {
		kind: typeReg, path: "./dir/file2", data: "bar", mode: 0644,
	}, {
		kind: typeLnk, path: "./dir/symlink", target: "./file1",
	}, {
		kind: typeHlk, path: "./dir/hardlink", target: "./dir/file2",
	}},
	expected: map[string]string{
		"/dir/":         "dir 0755",
		"/dir/file1":    "file 0644 2c26b46b",
		"/dir/file2":    "file 0644 fcde2b2e <1>",
		"/dir/symlink":  "symlink ./file1",
		"/dir/hardlink": "file 0644 fcde2b2e <1>",
	},
}}

func (s *S) TestTreeDump(c *C) {
	for _, test := range treeDumpTests {
		c.Logf("Summary: %s", test.summary)

		dir := c.MkDir()
		err := createTestDir(dir, test.files)
		c.Assert(err, IsNil)

		result := testutil.TreeDump(dir)
		c.Assert(result, DeepEquals, test.expected)
	}
}

func createTestDir(dir string, files []dirEntry) error {
	var err error
	for _, f := range files {
		path := filepath.Join(dir, f.path)
		switch f.kind {
		case typeDir:
			err = os.Mkdir(path, fs.FileMode(f.mode))
		case typeReg:
			err = os.WriteFile(path, []byte(f.data), fs.FileMode(f.mode))
		case typeLnk:
			err = os.Symlink(f.target, path)
		case typeHlk:
			targetPath := filepath.Join(dir, f.target)
			err = os.Link(targetPath, path)
		default:
			err = fmt.Errorf("unknown path kind")
		}
		if err != nil {
			return err
		}
	}
	return err
}
