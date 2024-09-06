package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

// The identifier for the hardlink is unique for each unique base file,
// which counts from 1. The 0 value is reserved for files that are not hard links.
type hardLinkRevMapEntry struct {
	Target      []string
	Identifier  int
	StagingPath string
}

type tarMetadata struct {
	HardLinkRevMap map[string]hardLinkRevMapEntry
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

// getDataReader returns a ReadCloser for the data payload of the package.
// Calling the Close method must happen outside of this function to prevent
// premature closing of the underlying package reader.
// The xz.Reader is wrapper with io.NopCloser since it does not implement the Close method.
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
	// stagingDir is the directory where the hard link base file, which is not
	// listed in the pendingPaths, to be extracted.
	stagingDir, err := os.MkdirTemp("", "chisel-staging-")
	if err != nil {
		return err
	}
	// Fist pass over the tarball to read the header of the tarball
	// and create its metadata.
	dataReader, err := getDataReader(pkgReader)
	if err != nil {
		return err
	}
	tarReader := tar.NewReader(dataReader)
	tarMetadata, err := readTarMetadata(tarReader)
	if err != nil {
		return err
	}
	// Rewind back to the start of the tarball and extract the files.
	pkgReader.Seek(0, io.SeekStart)
	// Second pass over the tarball to extract the files.
	dataReader, err = getDataReader(pkgReader)
	if err != nil {
		return err
	}
	defer dataReader.Close()

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

	// When creating a file we will iterate through its parent directories and
	// create them with the permissions defined in the tarball.
	//
	// The assumption is that the tar entries of the parent directories appear
	// before the entry for the file itself. This is the case for .deb files but
	// not for all tarballs.
	tarDirMode := make(map[string]fs.FileMode)
	tarReader = tar.NewReader(dataReader)
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// targetDir is the directory where the file is extracted.
		// It is either the options.TargetDir or the stagingDir.
		targetDir := options.TargetDir
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
			// Extract the hard link base file to the staging directory, when
			// 1. it is not part of the target paths (len(targetPaths) == 0)
			// 2. it is required by other hard links (exists as a key in the HardLinkRevMap)
			// In case that [len(targetPaths) > 0], the hard link base file is extracted normally.
			// Note that the hard link base file can also be a symlink.
			// tarHeader.Name is used here since the paths in the HardLinkRevMap are relative.
			if entry, ok := tarMetadata.HardLinkRevMap[tarHeader.Name]; ok {
				targetDir = stagingDir
				entry.StagingPath = filepath.Join(stagingDir, tarHeader.Name)
				tarMetadata.HardLinkRevMap[tarHeader.Name] = entry
				targetPaths[sourcePath] = append(targetPaths[sourcePath], ExtractInfo{
					Path: sourcePath,
					Mode: uint(tarHeader.FileInfo().Mode()),
				})
			} else {
				// Nothing to do.
				continue
			}
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
					Path:        filepath.Join(targetDir, path),
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
			hardLinkId := 0
			if tarHeader.Typeflag == tar.TypeLink {
				// Set the [link] to the absolute path if it's a hard link
				if entry, ok := tarMetadata.HardLinkRevMap[link]; ok {
					if entry.StagingPath != "" {
						link = entry.StagingPath
					} else {
						link = filepath.Join(targetDir, link)
					}
					// Set the hardLinkId for hard links
					hardLinkId = int(entry.Identifier)
				} else {
					return fmt.Errorf("hard link target %s not found in the tarball header", tarHeader.Linkname)
				}
			}
			// Set the HardLinkId to both the hard link and its counterpart file,
			// so they are symmetric in the report.
			if entry, ok := tarMetadata.HardLinkRevMap["."+targetPath]; ok {
				hardLinkId = int(entry.Identifier)
			}
			createOptions := &fsutil.CreateOptions{
				Path:        filepath.Join(targetDir, targetPath),
				Mode:        tarHeader.FileInfo().Mode(),
				Data:        pathReader,
				Link:        link,
				MakeParents: true,
				HardLinkId:  hardLinkId,
			}
			err := options.Create(extractInfos, createOptions)
			if err != nil {
				return err
			}
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

func newTarMetadata() tarMetadata {
	return tarMetadata{
		HardLinkRevMap: make(map[string]hardLinkRevMapEntry),
	}
}

func readTarMetadata(tarReader *tar.Reader) (tarMetadata, error) {
	metadata := newTarMetadata()
	var hardLinkRevMap = make(map[string][]string)
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return metadata, err
		}

		if tarHeader.Typeflag == tar.TypeLink {
			sourcePath := tarHeader.Name
			linkPath := tarHeader.Linkname
			hardLinkRevMap[linkPath] = append(hardLinkRevMap[linkPath], sourcePath)
		}
	}

	// Sort the hard link targets to ensure a deterministic HardLinkId in the report
	targets := make([]string, 0, len(hardLinkRevMap))
	for target := range hardLinkRevMap {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	for idx, target := range targets {
		sources := hardLinkRevMap[target]
		metadata.HardLinkRevMap[target] = hardLinkRevMapEntry{
			Target:      sources,
			Identifier:  idx + 1,
			StagingPath: "",
		}
	}

	return metadata, nil
}
