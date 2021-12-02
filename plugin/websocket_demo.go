// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package plugin

import (
	"net/http"

	"github.com/golang/glog"
	"github.com/gorilla/websocket"
	"github.com/truexf/goutil"
	"github.com/truxf/paddy"
)

type WebsocketPlugin struct {
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 32,
	WriteBufferSize: 1024 * 32,
}

// 唯一身份ID
func (m *WebsocketPlugin) ID() string {
	return "websocket"
}

// hijacked 是否劫持：true则必须实现respWriter写响应；false时不准向respWriter写响应，可以返回backend(此时框架直接去请求backend而不再走location匹配流程，否则框架执行location匹配)
func (m *WebsocketPlugin) RequestHeaderCompleted(req *http.Request, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, backend string, err goutil.Error) {
	if req.URL.Path == "/websocket_demo" {
		conn, err := wsUpgrader.Upgrade(respWriter, req, nil)
		if err != nil {
			return false, "", goutil.NewErrorf(paddy.ErrCodeCommonError, "upgrage conn to websocket fail, %s", err.Error())
		}
		// ... Use conn to send and receive messages.
		for {
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				glog.Errorf("websocket read fail, %s", err.Error())
				break
			}
			if err := conn.WriteMessage(messageType, p); err != nil {
				glog.Errorf("websocket write fail, %s", err.Error())
				break
			}
		}
		conn.Close()
		return true, "", paddy.ErrorNoError
	} else {
		return false, "", paddy.ErrorNoError
	}

}

// 框架在得到响应后，给客户端发送响应之前介入
// hijacked 是否劫持：true则必须实现respWriter写响应；false时，不准向respWriter写响应，可以返回newResponse(此时框架以newResponse写响应，否则以originResponse写响应）
func (m *WebsocketPlugin) ResponseHeaderCompleted(originResponse *http.Response, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, newResponse *http.Response, err goutil.Error) {
	return true, originResponse, paddy.ErrorNoError
}
