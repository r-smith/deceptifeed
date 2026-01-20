package logrotate

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Compile-time check to ensure File staisfies the io.WriteCloser interface.
var _ io.WriteCloser = (*File)(nil)

// File is an io.WriteCloser that supports appending data to a file and file
// rotation.
//
// The file is automatically rotated once the file size exceeds the maximum
// size limit (specified in megabytes). `File` should be created using the
// `OpenFile` function.
type File struct {
	name    string
	file    *os.File
	maxSize int64
	size    int64
	mu      sync.Mutex
}

// OpenFile opens the named file for appending. If successful, methods on the
// returned File can be used for I/O. When writing to the file, it will
// automatically rotate once the file size exceeds maxSizeMB (specified in
// megabytes).
func OpenFile(name string, maxSizeMB int) (*File, error) {
	if maxSizeMB < 1 {
		return nil, fmt.Errorf("maxSizeMB must be greater than 0")
	}

	// Open the file for appending.
	file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	// Get the current file size.
	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	return &File{
		file:    file,
		name:    name,
		maxSize: int64(maxSizeMB) * 1024 * 1024, // Convert MB to bytes
		size:    stat.Size(),
	}, nil
}

// rotate checks if the file size exceeds the maximum allowed size. If so, it
// renames the current file by appending ".1" to its name and opens a new file
// with the original name. If a file with the ".1" suffix already exists, it is
// replaced.
func (f *File) rotate() error {
	if f.file == nil {
		return fmt.Errorf("file already closed")
	}

	// Return if rotation isn't needed.
	if f.size < f.maxSize {
		return nil
	}

	// Capture the current file's permissions, defaulting to 0644.
	info, _ := f.file.Stat()
	mode := os.FileMode(0644)
	if info != nil {
		mode = info.Mode().Perm()
	}

	// Close the current file. Proceed even if Close returns an error to keep
	// the logger operational.
	_ = f.file.Close()

	// Rotate the file to ".1". Proceed even if Rename returns an error to keep
	// the logger operational.
	_ = os.Rename(f.name, f.name+".1")

	// Open new file with the original permissions.
	newFile, err := os.OpenFile(f.name, os.O_APPEND|os.O_WRONLY|os.O_CREATE, mode)
	if err != nil {
		return fmt.Errorf("can't open new file: %w", err)
	}

	// Reassign file and reset the size.
	f.file = newFile
	f.size = 0
	return nil
}

// Write writes len(b) bytes from b to the File. If the File's size exceeds its
// maxSize, the file is renamed, a new file is opened with the orginal name,
// and the write is applied to the new file. Write returns the number of bytes
// written and an error, if any. Write returns a non-nil error when n != len(b).
func (f *File) Write(b []byte) (n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file == nil {
		return 0, os.ErrClosed
	}

	// Rotate the log file if needed.
	err = f.rotate()
	if err != nil {
		return 0, fmt.Errorf("logrotate failed: %w", err)
	}

	// Write the data and update the size.
	n, err = f.file.Write(b)
	f.size += int64(n)
	return n, err
}

// Close closes the File, rendering it unusable for I/O. Close will return an
// error if it has already been called.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file == nil {
		return nil
	}

	err := f.file.Close()
	f.file = nil
	return err
}
