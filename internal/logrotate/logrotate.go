package logrotate

import (
	"fmt"
	"os"
	"sync"
)

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
// automatically rotate once the file size exceeds the maxSize (specified in
// megabytes).
func OpenFile(name string, maxSize int) (*File, error) {
	if maxSize < 1 {
		return nil, fmt.Errorf("maxSize must be greater than 0")
	}

	// Open the file for appending.
	file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	// Get the current file size.
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}

	return &File{
		file:    file,
		name:    name,
		maxSize: int64(maxSize) * 1024 * 1024, // Convert to megabytes
		size:    stat.Size(),
	}, nil
}

// rotate checks if the file size exceeds the maximum allowed size. If so, it
// renames the current file by appending ".1" to its name and opens a new file
// with the original name. If a file with the ".1" suffix already exists, it is
// replaced.
func (f *File) rotate() error {
	if f.size > f.maxSize {
		// Retrieve the file information for the current file to capture its
		// permissions. Any errors encountered are handled later and do not
		// affect the rotation process.
		info, statErr := f.file.Stat()

		// Close the current file.
		if err := f.file.Close(); err != nil {
			return fmt.Errorf("can't close file: %w", err)
		}

		// Rename the file with a ".1" suffix.
		if err := os.Rename(f.name, f.name+".1"); err != nil {
			return fmt.Errorf("can't rename file: %w", err)
		}

		// Open a new file with the original name.
		file, err := os.OpenFile(f.name, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("can't create new file: %w", err)
		}

		// Apply the original permissions to the new file. This is a
		// best-effort operation that only runs if the previous os.Stat call
		// was successful. Any errors from chmod are ignored.
		if statErr == nil {
			_ = file.Chmod(info.Mode().Perm())
		}

		// Reassign file and reset the size.
		f.file = file
		f.size = 0
	}
	return nil
}

// Write writes len(b) bytes from b to the File. If the File's size exceeds its
// maxSize, the file is renamed, a new file is opened with the orginal name,
// and the write is applied to the new file. Write returns the number of bytes
// written and an error, if any. Write returns a non-nil error when n != len(b).
func (f *File) Write(b []byte) (n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Rotate the log file if needed.
	err = f.rotate()
	if err != nil {
		return 0, fmt.Errorf("log rotate: %w", err)
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

	err := f.file.Close()
	f.file = nil
	return err
}
