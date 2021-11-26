// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import (
	"net/http"

	"github.com/truexf/goutil"
)

type FileServer struct {
}

func (m *FileServer) serve(fileRoot string, r *http.Request, w http.ResponseWriter) (done bool, err goutil.Error) {
	// todo
	return false, ErrorNoError
}
