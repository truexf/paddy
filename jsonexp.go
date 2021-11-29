// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/golang/glog"
	"github.com/truexf/goutil"
)

const (
	JsonExpVarProxyPass   = "$proxy_pass"
	JsonExpVarBackend     = "$backend"
	JsonExpVarFileRoot    = "$file_root"
	JsonExpVarSetResponse = "$set_response"

	JsonExpObjRequest        = "$req"
	JsonExpObjRequestHeader  = "$req_header"
	JsonExpObjRequestParam   = "$req_param"
	JsonExpObjResponse       = "$resp"
	JsonExpObjResponseHeader = "$resp_header"

	JsonExpObjRequestInstance        = "$req"
	JsonExpObjRequestHeaderInstance  = "$req_header"
	JsonExpObjRequestParamInstance   = "$req_param"
	JsonExpObjResponseInstance       = "$resp"
	JsonExpObjResponseHeaderInstance = "$resp_header"

	JsonExpObjPropRequestVer    = "ver"
	JsonExpObjPropRequestHost   = "host"
	JsonExpObjPropRequestPath   = "path"
	JsonExpObjPropRequestURI    = "uri"
	JsonExpObjPropRequestMethod = "method"

	JsonExpObjPropResponseStatus = "status"
	JsonExpObjPropResponseBody   = "body"
)

type RequestObj struct {
	ver    string
	path   string
	uri    string
	host   string
	method string

	data goutil.Context
}

func newRequestObj(r *http.Request) *RequestObj {
	return &RequestObj{
		ver:    fmt.Sprintf("%d.%d", r.ProtoMajor, r.ProtoMinor),
		path:   r.URL.Path,
		uri:    r.RequestURI,
		host:   r.Host,
		method: r.Method,
	}
}

func requestObjFromContext(context goutil.Context) *RequestObj {
	i, ok := context.GetCtxData(JsonExpObjRequestInstance)
	if ok && i != nil {
		return i.(*RequestObj)
	}
	return nil
}

func (o *RequestObj) GetPropertyValue(property string, context goutil.Context) interface{} {
	// instance was set into context before
	m := requestObjFromContext(context)
	if m == nil {
		return nil
	}

	switch property {
	case JsonExpObjPropRequestVer:
		return m.ver
	case JsonExpObjPropRequestHost:
		return m.host
	case JsonExpObjPropRequestPath:
		return m.path
	case JsonExpObjPropRequestURI:
		return m.uri
	case JsonExpObjPropRequestMethod:
		return m.method
	default:
		ret, _ := m.data.GetCtxData(property)
		return ret
	}
}
func (o *RequestObj) SetPropertyValue(property string, value interface{}, context goutil.Context) {
	// instance was set into context before
	m := requestObjFromContext(context)
	if m == nil {
		return
	}

	switch property {
	case JsonExpObjPropRequestVer:
		m.ver = goutil.GetStringValue(value)
	case JsonExpObjPropRequestHost:
		m.host = goutil.GetStringValue(value)
	case JsonExpObjPropRequestPath:
		m.path = goutil.GetStringValue(value)
	case JsonExpObjPropRequestURI:
		m.uri = goutil.GetStringValue(value)
	case JsonExpObjPropRequestMethod:
		m.method = goutil.GetStringValue(value)
	}
}

type RequestHeaderObj struct {
	header http.Header
}

func newRequestHeaderObj(r *http.Request) *RequestHeaderObj {
	return &RequestHeaderObj{
		header: r.Header,
	}
}

func requestHeaderObjFromContext(context goutil.Context) *RequestHeaderObj {
	if i, ok := context.GetCtxData(JsonExpObjRequestHeaderInstance); ok && i != nil {
		return i.(*RequestHeaderObj)
	}
	return nil
}

func (o *RequestHeaderObj) GetPropertyValue(property string, context goutil.Context) interface{} {
	return o.header.Get(property)
}
func (o *RequestHeaderObj) SetPropertyValue(property string, value interface{}, context goutil.Context) {
	o.header.Set(property, goutil.GetStringValue(value))
}

type RequestParamObj struct {
	params url.Values
}

func newRequestParamObj(r *http.Request) *RequestParamObj {
	return &RequestParamObj{
		params: r.URL.Query(),
	}
}

func requestParamObjFromContext(context goutil.Context) *RequestParamObj {
	if i, ok := context.GetCtxData(JsonExpObjRequestParamInstance); ok && i != nil {
		return i.(*RequestParamObj)
	}
	return nil
}

func (o *RequestParamObj) GetPropertyValue(property string, context goutil.Context) interface{} {
	return o.params.Get(property)
}
func (o *RequestParamObj) SetPropertyValue(property string, value interface{}, context goutil.Context) {
	o.params.Set(property, goutil.GetStringValue(value))
}

type ResponseObj struct {
	status       int
	body         []byte
	bodyModified bool
}

func newResponseObj(resp *http.Response) *ResponseObj {
	return &ResponseObj{
		status: resp.StatusCode,
	}
}

func responseObjFromContext(context goutil.Context) *ResponseObj {
	if i, ok := context.GetCtxData(JsonExpObjResponseInstance); ok && i != nil {
		return i.(*ResponseObj)
	}
	return nil
}

func (o *ResponseObj) GetPropertyValue(property string, context goutil.Context) interface{} {
	if property == JsonExpObjPropResponseStatus {
		return o.status
	}
	return nil
}
func (o *ResponseObj) SetPropertyValue(property string, value interface{}, context goutil.Context) {
	if property == JsonExpObjPropResponseStatus {
		if i, ok := goutil.GetIntValue(value); ok {
			o.status = int(i)
		}
	} else if property == JsonExpObjPropResponseBody {
		o.body = []byte(goutil.GetStringValue(value))
		o.bodyModified = true
	}
}

type ResponseHeaderObj struct {
	header http.Header
}

func newResponseHeaderObj(resp *http.Response) *ResponseHeaderObj {
	return &ResponseHeaderObj{
		header: resp.Header,
	}
}

func responseHeaderObjFromContext(context goutil.Context) *ResponseHeaderObj {
	if i, ok := context.GetCtxData(JsonExpObjResponseHeaderInstance); ok && i != nil {
		return i.(*ResponseHeaderObj)
	}
	return nil
}

func (o *ResponseHeaderObj) GetPropertyValue(property string, context goutil.Context) interface{} {
	return o.header.Get(property)
}
func (o *ResponseHeaderObj) SetPropertyValue(property string, value interface{}, context goutil.Context) {
	o.header.Set(property, goutil.GetStringValue(value))
}

func findResponse(context goutil.Context) (*ResponseObj, *ResponseHeaderObj) {
	return responseObjFromContext(context), responseHeaderObjFromContext(context)
}

func writeResponseUseContext(w http.ResponseWriter, context goutil.Context) (writted bool) {
	resp, resph := findResponse(context)
	if resp != nil && resp.status > 0 {
		w.WriteHeader(resp.status)
		w.Write(resp.body)
		for k, v := range resph.header {
			if len(v) > 0 {
				w.Header().Set(k, v[0])
			}
		}
		return true
	}
	return false
}

func rewriteResponseUseContext(resp *http.Response, context goutil.Context) {
	ro, roh := findResponse(context)
	if ro != nil && roh != nil {
		resp.StatusCode = ro.status
		if ro.bodyModified {
			resp.Body = io.NopCloser(bytes.NewBuffer(ro.body))
		}
		for k, v := range roh.header {
			if len(v) > 0 {
				resp.Header.Set(k, v[0])
			}
		}
	}
}

func rewriteRequestUseContext(originRequest *http.Request, context goutil.Context) (newRequest *http.Request) {
	ro, roh, rop := requestObjFromContext(context), requestHeaderObjFromContext(context), requestParamObjFromContext(context)
	if ro != nil && roh != nil && rop != nil {
		u, err := url.ParseRequestURI(ro.uri)
		if err != nil {
			glog.Errorf("rewriteRequestUseContext, %s", err.Error())
			return originRequest
		}
		q := u.Query()
		paramModified := false
		for k, v := range rop.params {
			if len(v) > 0 {
				oldValue, ok := q[k]
				if !ok || len(oldValue) == 0 {
					paramModified = true
				} else {
					if oldValue[0] != v[0] {
						paramModified = true
					}
				}
				if paramModified {
					q.Set(k, v[0])
				}
			}
		}
		if paramModified || ro.path != originRequest.URL.Path {
			ro.uri = fmt.Sprintf("%s?%s", ro.path, q.Encode())
			if originRequest.URL, err = url.ParseRequestURI(ro.uri); err != nil {
				glog.Errorf("ParseRequestURI [%s] fail, %s", ro.uri, err.Error())
				return originRequest
			}
		}
		if originRequest.Host != ro.host {
			originRequest.Host = ro.host
			originRequest.URL.Host = ro.host
		}

		for k, v := range roh.header {
			if len(v) > 0 {
				originRequest.Header.Set(k, v[0])
			}
		}
	}
	return originRequest
}
