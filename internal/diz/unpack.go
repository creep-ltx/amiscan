package diz

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Unpack writes every file of an archive (any format Contents reads) under dest, folders
// made as needed. A member whose path would leave dest is refused, and so is an archive
// that unpacks to more than limit bytes. It returns the files written, '/' separated.
func Unpack(path, dest string, limit int64) (files []string, err error) {
	f, size, f0, err := sniff(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f0 == nil {
		return nil, errors.New("not an archive BBX can read")
	}
	defer func() {
		if r := recover(); r != nil { // a decoder bug on strange data must not take the board down
			files, err = nil, fmt.Errorf("the archive is damaged: %v", r)
		}
	}()
	ms, _, ok := listAll(f, size, f0)
	if !ok {
		return nil, errors.New("the archive cannot be read")
	}
	var total int64
	for _, m := range ms {
		if m.dir || m.read == nil || m.name == "." || m.name == "" {
			continue
		}
		if strings.HasPrefix(m.name, "../") || m.name == ".." || filepath.IsAbs(m.name) {
			return files, fmt.Errorf("the archive holds %q, outside its folder", m.name)
		}
		data, err := m.read(limit - total + 1)
		if err != nil {
			return files, fmt.Errorf("%s: %w", m.name, err)
		}
		if total += int64(len(data)); total > limit {
			return files, fmt.Errorf("the archive unpacks to more than %d MB", limit>>20)
		}
		to := filepath.Join(dest, filepath.FromSlash(m.name))
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return files, err
		}
		if err := os.WriteFile(to, data, 0o644); err != nil {
			return files, err
		}
		files = append(files, m.name)
	}
	return files, nil
}
