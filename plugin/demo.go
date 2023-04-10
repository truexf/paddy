// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package plugin

import (
	"bytes"
	"io"
	"net/http"

	"github.com/truexf/goutil"
	"github.com/truxf/paddy"
)

type DemoPlugin struct {
}

// 唯一身份ID
func (m *DemoPlugin) ID() string {
	return "demo"
}

// hijacked 是否劫持：true则必须实现respWriter写响应；false时不准向respWriter写响应，可以返回backend(此时框架直接去请求backend而不再走location匹配流程，否则框架执行location匹配)
func (m *DemoPlugin) RequestHeaderCompleted(req *http.Request, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, proxyPass, backend string, err goutil.Error) {
	if req.URL.Path == "/ping" {
		respWriter.WriteHeader(200)
		respWriter.Write(goutil.UnsafeStringToBytes("pong"))
		return true, "", "", paddy.ErrorNoError
	} else {
		return false, "", "", paddy.ErrorNoError
	}
}

// 框架在得到响应后，给客户端发送响应之前介入
// hijacked 是否劫持：true则必须实现respWriter写响应；false时，不准向respWriter写响应，可以返回newResponse(此时框架以newResponse写响应，否则以originResponse写响应）
func (m *DemoPlugin) ResponseHeaderCompleted(originResponse *http.Response, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, newResponse *http.Response, err goutil.Error) {
	var bodyBuf bytes.Buffer
	if _, err := io.Copy(&bodyBuf, originResponse.Body); err != nil {
		return false, nil, goutil.NewErrorf(paddy.ErrCodeDemo, paddy.ErrMsgDemo, err.Error())
	}
	bodyBuf.WriteString("append demo data to response body")
	originResponse.Body = io.NopCloser(&bodyBuf)
	return true, originResponse, paddy.ErrorNoError
}
