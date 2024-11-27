package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/blakesmith/ar"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/canonical/chisel/internal/fsutil"
	"github.com/canonical/chisel/internal/strdist"
)

type ExtractOptions struct {
	Package   string
	TargetDir string
	Extract   map[string][]ExtractInfo
	// Create can optionally be set to control the creation of extracted entries.
	// extractInfos is set to the matching entries in Extract, and is nil in cases where
	// the created entry is implicit and unlisted (for example, parent directories).
	Create func(extractInfos []ExtractInfo, options *fsutil.CreateOptions) error
}

type ExtractInfo struct {
	Path     string
	Mode     uint
	Optional bool
	Context  any
}

type HardLinkInfo struct {
	// The target path of the hard link logged in the tarball header.
	TargetPath string
	// Info of the hard links to extract, which has the link target TargetPath.
	ExtractInfos []ExtractInfo
}

func getValidOptions(options *ExtractOptions) (*ExtractOptions, error) {
	for extractPath, extractInfos := range options.Extract {
		isGlob := strings.ContainsAny(extractPath, "*?")
		if isGlob {
			for _, extractInfo := range extractInfos {
				if extractInfo.Path != extractPath || extractInfo.Mode != 0 {
					return nil, fmt.Errorf("when using wildcards source and target paths must match: %s", extractPath)
				}
			}
		}
	}

	if options.Create == nil {
		validOpts := *options
		validOpts.Create = func(_ []ExtractInfo, o *fsutil.CreateOptions) error {
			_, err := fsutil.Create(o)
			return err
		}
		return &validOpts, nil
	}

	return options, nil
}

func Extract(pkgReader io.ReadSeeker, options *ExtractOptions) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("cannot extract from package %q: %w", options.Package, err)
		}
	}()

	logf("Extracting files from package %q...", options.Package)

	validOpts, err := getValidOptions(options)
	if err != nil {
		return err
	}

	_, err = os.Stat(validOpts.TargetDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("target directory does not exist")
	} else if err != nil {
		return err
	}

	return extractData(pkgReader, validOpts)
}

func getDataReader(pkgReader io.ReadSeeker) (io.ReadCloser, error) {
	arReader := ar.NewReader(pkgReader)
	var dataReader io.ReadCloser
	for dataReader == nil {
		arHeader, err := arReader.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no data payload")
		}
		if err != nil {
			return nil, err
		}
		switch arHeader.Name {
		case "data.tar.gz":
			gzipReader, err := gzip.NewReader(arReader)
			if err != nil {
				return nil, err
			}
			dataReader = gzipReader
		case "data.tar.xz":
			xzReader, err := xz.NewReader(arReader)
			if err != nil {
				return nil, err
			}
			dataReader = io.NopCloser(xzReader)
		case "data.tar.zst":
			zstdReader, err := zstd.NewReader(arReader)
			if err != nil {
				return nil, err
			}
			dataReader = zstdReader.IOReadCloser()
		}
	}

	return dataReader, nil
}

func extractData(pkgReader io.ReadSeeker, options *ExtractOptions) error {

	dataReader, err := getDataReader(pkgReader)
	if err != nil {
		return err
	}

	oldUmask := syscall.Umask(0)
	defer func() {
		syscall.Umask(oldUmask)
	}()

	pendingPaths := make(map[string]bool)
	for extractPath, extractInfos := range options.Extract {
		for _, extractInfo := range extractInfos {
			if !extractInfo.Optional {
				pendingPaths[extractPath] = true
				break
			}
		}
	}

	pendingHardLinks := make(map[string][]HardLinkInfo)

	// When creating a file we will iterate through its parent directories and
	// create them with the permissions defined in the tarball.
	//
	// The assumption is that the tar entries of the parent directories appear
	// before the entry for the file itself. This is the case for .deb files but
	// not for all tarballs.
	tarDirMode := make(map[string]fs.FileMode)
	tarReader := tar.NewReader(dataReader)
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		sourcePath := tarHeader.Name
		if len(sourcePath) < 3 || sourcePath[0] != '.' || sourcePath[1] != '/' {
			continue
		}
		sourcePath = sourcePath[1:]
		if sourcePath == "" {
			continue
		}

		sourceIsDir := sourcePath[len(sourcePath)-1] == '/'
		if sourceIsDir {
			tarDirMode[sourcePath] = tarHeader.FileInfo().Mode()
		}

		// Find all globs and copies that require this source, and map them by
		// their target paths on disk.
		targetPaths := map[string][]ExtractInfo{}
		for extractPath, extractInfos := range options.Extract {
			if extractPath == "" {
				continue
			}
			if strings.ContainsAny(extractPath, "*?") {
				if strdist.GlobPath(extractPath, sourcePath) {
					targetPaths[sourcePath] = append(targetPaths[sourcePath], extractInfos...)
					delete(pendingPaths, extractPath)
				}
			} else if extractPath == sourcePath {
				for _, extractInfo := range extractInfos {
					targetPaths[extractInfo.Path] = append(targetPaths[extractInfo.Path], extractInfo)
				}
				delete(pendingPaths, extractPath)
			}
		}
		if len(targetPaths) == 0 {
			// Nothing to do.
			continue
		}

		var contentCache []byte
		var contentIsCached = len(targetPaths) > 1 && !sourceIsDir
		if contentIsCached {
			// Read and cache the content so it may be reused.
			// As an alternative, to avoid having an entire file in
			// memory at once this logic might open the first file
			// written and copy it every time. For now, the choice
			// is speed over memory efficiency.
			data, err := io.ReadAll(tarReader)
			if err != nil {
				return err
			}
			contentCache = data
		}

		var pathReader io.Reader = tarReader
		for targetPath, extractInfos := range targetPaths {
			if contentIsCached {
				pathReader = bytes.NewReader(contentCache)
			}
			mode := extractInfos[0].Mode
			for _, extractInfo := range extractInfos {
				if extractInfo.Mode != mode {
					if mode < extractInfo.Mode {
						mode, extractInfo.Mode = extractInfo.Mode, mode
					}
					return fmt.Errorf("path %s requested twice with diverging mode: 0%03o != 0%03o", targetPath, mode, extractInfo.Mode)
				}
			}
			if mode != 0 {
				tarHeader.Mode = int64(mode)
			}
			// Create the parent directories using the permissions from the tarball.
			parents := parentDirs(targetPath)
			for _, path := range parents {
				if path == "/" {
					continue
				}
				mode, ok := tarDirMode[path]
				if !ok {
					continue
				}
				delete(tarDirMode, path)

				createOptions := &fsutil.CreateOptions{
					Path:        filepath.Join(options.TargetDir, path),
					Mode:        mode,
					MakeParents: true,
				}
				err := options.Create(nil, createOptions)
				if err != nil {
					return err
				}
			}
			// Create the entry itself.
			link := tarHeader.Linkname
			if tarHeader.Typeflag == tar.TypeLink {
				// A hard link requires the real path of the target file.
				link = filepath.Join(options.TargetDir, link)
			}

			createOptions := &fsutil.CreateOptions{
				Path:         filepath.Join(options.TargetDir, targetPath),
				Mode:         tarHeader.FileInfo().Mode(),
				Data:         pathReader,
				Link:         link,
				MakeParents:  true,
				OverrideMode: true,
			}
			err := options.Create(extractInfos, createOptions)
			if err != nil {
				if errors.Is(err, fsutil.ErrLinkTargetNotExist) && tarHeader.Typeflag == tar.TypeLink {
					// This means that the hard link target file has not been
					// extracted. Add this hard link entry to the pending list
					// to extract later.
					basePath := sanitizeTarSourcePath(tarHeader.Linkname)
					info := HardLinkInfo{
						TargetPath:   targetPath,
						ExtractInfos: extractInfos,
					}
					pendingHardLinks[basePath] = append(pendingHardLinks[basePath], info)
					pendingPaths[basePath] = true
				} else {
					return err
				}
			}
		}
	}

	// Go over the tarball again to textract the pending hard links.
	if len(pendingHardLinks) > 0 {
		offset, err := pkgReader.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}
		if offset != 0 {
			return fmt.Errorf("cannot seek to the beginning of the package")
		}
		dataReader, err = getDataReader(pkgReader)
		if err != nil {
			return err
		}
		tarReader := tar.NewReader(dataReader)
		err = handlePendingHardLinks(options, pendingHardLinks, tarReader, pendingPaths)
		if err != nil {
			return err
		}
	}

	if len(pendingPaths) > 0 {
		pendingList := make([]string, 0, len(pendingPaths))
		for pendingPath := range pendingPaths {
			pendingList = append(pendingList, pendingPath)
		}
		if len(pendingList) == 1 {
			return fmt.Errorf("no content at %s", pendingList[0])
		} else {
			sort.Strings(pendingList)
			return fmt.Errorf("no content at:\n- %s", strings.Join(pendingList, "\n- "))
		}
	}

	dataReader.Close()

	return nil
}

func handlePendingHardLinks(options *ExtractOptions, pendingHardLinks map[string][]HardLinkInfo,
	tarReader *tar.Reader, pendingPaths map[string]bool) error {
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		sourcePath := sanitizeTarSourcePath(tarHeader.Name)
		if sourcePath == "" {
			continue
		}

		hardLinks, ok := pendingHardLinks[sourcePath]
		if !ok || len(hardLinks) == 0 {
			continue
		}

		// Since the hard link target file was not extracted in the first pass,
		// we extract the first hard link as a regular file. For the rest of
		// the hard link entries, we link those paths to first file extracted.
		targetPath := hardLinks[0].TargetPath
		extractPath := filepath.Join(options.TargetDir, targetPath)
		// Write the content for the first file in the hard link group
		createOptions := &fsutil.CreateOptions{
			Path: extractPath,
			Mode: tarHeader.FileInfo().Mode(),
			Data: tarReader,
		}

		err = options.Create(hardLinks[0].ExtractInfos, createOptions)
		if err != nil {
			return err
		}
		delete(pendingPaths, sourcePath)
		delete(pendingPaths, targetPath)

		// Create the remaining hard links.
		for _, hardLink := range hardLinks[1:] {
			createOptions := &fsutil.CreateOptions{
				Path: filepath.Join(options.TargetDir, hardLink.TargetPath),
				Mode: tarHeader.FileInfo().Mode(),
				// Link to the first file extracted for the hard links.
				Link: extractPath,
			}
			err := options.Create(hardLink.ExtractInfos, createOptions)
			if err != nil {
				return err
			}
			delete(pendingPaths, hardLink.TargetPath)
		}
	}
	return nil
}

func parentDirs(path string) []string {
	path = filepath.Clean(path)
	parents := make([]string, strings.Count(path, "/"))
	count := 0
	for i, c := range path {
		if c == '/' {
			parents[count] = path[:i+1]
			count++
		}
	}
	return parents
}

// sanitizeTarSourcePath removes the leading "./" from the source path in the tarball,
// and verifies that the path is not empty.
func sanitizeTarSourcePath(path string) string {
	if len(path) < 3 || path[0] != '.' || path[1] != '/' {
		return ""
	}
	path = path[1:]
	return path
}
