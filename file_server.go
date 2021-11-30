// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/truexf/goutil"
)

const (
	DefaultCacheFileSizeLimit = 30 * 1024 * 1024

	ErrCodeFSNormal         = 200
	ErrCodeFSFileNotChanged = 201
	ErrMsgFSFileNotChanged  = "file not changed"
)

type FileServer struct {
	maxCacheFileSize int64
	fileCache        map[string]*goutil.LRUFileCache
	lock             sync.RWMutex
}

func NewFileServer(maxCacheFileSize int64) *FileServer {
	ret := &FileServer{maxCacheFileSize: maxCacheFileSize}
	ret.fileCache = make(map[string]*goutil.LRUFileCache)
	return ret
}

func (m *FileServer) getOrCreateCache(fileRootPath string) (*goutil.LRUFileCache, error) {
	if fileRootPath == "" || !goutil.FilePathExists(fileRootPath) {
		return nil, goutil.ErrorFileNotExists
	}
	m.lock.RLock()
	ret, ok := m.fileCache[fileRootPath]
	if ok {
		m.lock.RUnlock()
		return ret, nil
	}
	m.lock.RUnlock()
	m.lock.Lock()
	defer m.lock.Unlock()
	ret = goutil.NewLRUFileCache(m.maxCacheFileSize, 0)
	m.fileCache[fileRootPath] = ret
	return ret, nil
}

func (m *FileServer) serve(fileRoot string, r *http.Request, w http.ResponseWriter) (done bool, e goutil.Error) {
	if fileRoot == "" || r == nil || w == nil {
		return false, goutil.NewError(ErrCodeFSNormal, "invalid param of FileServer.serve")
	}

	lruCache, err := m.getOrCreateCache(fileRoot)
	if err != nil {
		return false, goutil.NewError(ErrCodeFSNormal, err.Error())
	}
	since := time.Time{}
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		if t, err := http.ParseTime(ifModifiedSince); err == nil {
			since = t
		}
	}
	fn := filepath.Join(fileRoot, r.URL.Path)
	ret, err := lruCache.Get(filepath.Join(fileRoot, r.URL.Path), since)
	if err != nil {
		if err != goutil.ErrorFileSizeLimited {
			return false, goutil.NewError(ErrCodeFSNormal, err.Error())
		}
		fd, err := os.Open(fn)
		if err != nil {
			return false, goutil.NewError(ErrCodeFSNormal, err.Error())
		}
		if _, err := io.Copy(w, fd); err != nil {
			return false, goutil.NewError(ErrCodeFSNormal, err.Error())
		}
		if st, err := fd.Stat(); err == nil {
			w.Header().Set("Last-Modified", st.ModTime().UTC().Format(http.TimeFormat))
		}
		return true, ErrorNoError

	}
	w.Header().Set("Last-Modified", ret.ModifyTime.UTC().Format(http.TimeFormat))
	w.Write(ret.Data)
	return true, ErrorNoError
}
