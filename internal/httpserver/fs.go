package httpserver

import "io/fs"

// noDirectoryFS is a wrapper around fs.FS that disables directory listings.
type noDirectoryFS struct {
	fs fs.FS
}

// Open opens the named file from the underlying fs.FS. The file is wrapped in
// a noReadDirFile to disable directory listings.
func (fs noDirectoryFS) Open(name string) (fs.File, error) {
	f, err := fs.fs.Open(name)
	if err != nil {
		return nil, err
	}
	return noReadDirFile{f}, nil
}

// noReadDirFile wraps fs.File and overrides ReadDir to disable directory
// listings.
type noReadDirFile struct {
	fs.File
}

// ReadDir always returns an error to disable directory listings.
func (noReadDirFile) ReadDir(int) ([]fs.DirEntry, error) {
	return nil, fs.ErrInvalid
}
