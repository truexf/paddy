// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/truexf/goutil"
	"github.com/truexf/goutil/jsonexp"
	"github.com/truexf/goutil/lblhttpclient"
)

// 插件接口
type Plugin interface {
	// 唯一身份ID
	ID() string

	// 在http请求接收完成后介入
	// hijacked 是否劫持：true则必须实现respWriter写响应；false时不准向respWriter写响应，可以返回backend(此时框架直接去请求backend而不再走location匹配流程，否则框架执行location匹配)
	RequestHeaderCompleted(req *http.Request, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, backend string, err goutil.Error)

	// 框架在得到响应后，给客户端发送响应之前介入
	// hijacked 是否劫持：true则必须实现respWriter写响应；false时，不准向respWriter写响应，可以返回newResponse(此时框架以newResponse写响应，否则以originResponse写响应）
	ResponseHeaderCompleted(originResponse *http.Response, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, newResponse *http.Response, err goutil.Error)
}

type Backend struct {
	Ip     string
	Port   uint16
	Weight int
}

type BackendGroup struct {
	Name        string
	BackendList []Backend
}

type BackendDef struct {
	Alias               string
	BackendList         []Backend
	backendGroupList    []string
	Method              string
	ParamKey            string
	JsonExp             *jsonexp.JsonExpGroup
	MaxIdleConn         int
	WaitResponseTiemout time.Duration
	lbClient            *lblhttpclient.LblHttpClient
}

type RegexpLocationItem struct {
	uriRegexp      *regexp.Regexp
	backend        string
	fileRoot       string
	requestFilter  *jsonexp.JsonExpGroup
	responseFilter *jsonexp.JsonExpGroup
}

// 基于正则表达式的location配置
type RegexpLocation struct {
	Items []*RegexpLocationItem
}

// 基于jsonexp的location配置项
type JsonexpLocation struct {
	Exp            *jsonexp.JsonExpGroup
	requestFilter  *jsonexp.JsonExpGroup
	responseFilter *jsonexp.JsonExpGroup
}

type Listener struct {
	port        uint16
	tls         bool
	tcpListener *net.TCPListener
	httpServer  *http.Server
}

// 虚拟服务器配置
type VirtualServer struct {
	listenPorts     map[uint16]bool // value is tls
	hosts           map[string][]byte
	tlsCert         string
	tlsCertKey      string
	regexpLocation  *RegexpLocation
	jsonexpLocation *JsonexpLocation

	listeners map[uint16]*Listener
}

func (m *VirtualServer) init() {
	m.listenPorts = make(map[uint16]bool)
	m.listeners = make(map[uint16]*Listener)
	m.hosts = make(map[string][]byte)
}

type PaddyHandler struct {
	paddy *Paddy
}

func (m *PaddyHandler) pluginRequestAdapter(plugin Plugin, req *http.Request, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, backend string, err goutil.Error) {
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("%s plugin request panic: %s", time.Now().String(), err)
			buf := make([]byte, 81920)
			n := runtime.Stack(buf, true)
			if n > 0 {
				buf = buf[:n]
				glog.Errorln(string(buf))
			} else {
				glog.Errorln("no stack trace")
			}
			glog.Flush()
		}
	}()
	return plugin.RequestHeaderCompleted(req, respWriter, context)
}

func (m *PaddyHandler) pluginResponseAdapter(plugin Plugin, originResponse *http.Response, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, newResponse *http.Response, err goutil.Error) {
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("%s plugin response panic: %s", time.Now().String(), err)
			buf := make([]byte, 81920)
			n := runtime.Stack(buf, true)
			if n > 0 {
				buf = buf[:n]
				glog.Errorln(string(buf))
			} else {
				glog.Errorln("no stack trace")
			}
			glog.Flush()
		}
	}()
	return plugin.ResponseHeaderCompleted(originResponse, respWriter, context)
}

func (m *PaddyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !m.paddy.ready {
		w.WriteHeader(500)
		w.Write([]byte("not ready"))
		return
	}
	context := &goutil.DefaultContext{}
	var hijacked bool
	var done bool
	var backend string
	var err goutil.Error
	var resp *http.Response

	for _, plugin := range m.paddy.plugin {
		hijacked, backend, err = m.pluginRequestAdapter(plugin, r, w, context)
		if err.Code != ErrCodeNoError {
			glog.Errorf("call plugin request: %s fail,%d, %s", plugin.ID(), err.Code, err.Error())
			w.WriteHeader(500)
			return
		}
		if hijacked {
			return
		}
		if backend != "" {
			break
		}
	}

	context.SetCtxData(JsonExpObjRequestInstance, newRequestObj(r))
	context.SetCtxData(JsonExpObjRequestHeaderInstance, newRequestHeaderObj(r))
	context.SetCtxData(JsonExpObjRequestParamInstance, newRequestParamObj(r))

	doLoop := true
	for {
		// only onece
		if !doLoop {
			break
		} else {
			doLoop = !doLoop
		}

		if backend == "" {
			done, backend, resp, err = m.paddy.doLocation(r, w, context)
			if err.Code != ErrCodeNoError {
				glog.Errorf("uri: %s, do location fail, %d, %s", r.RequestURI, err.Code, err.Error())
				break
			}
			if done {
				return
			}
			if backend == "" && resp == nil {
				resp = &http.Response{StatusCode: 404}
				break
			}
		}

		if resp == nil {
			resp, err = m.paddy.doBackend(backend, r, context)
			if err.Code != ErrCodeNoError {
				glog.Errorf("uri: %s, do backend: %s fail, %d, %s", r.RequestURI, backend, err.Code, err.Error())
				break
			}
		}

	}

	if err.Code != ErrCodeNoError {
		w.WriteHeader(500)
		return
	}

	if resp != nil {
		context.SetCtxData(JsonExpObjResponseInstance, newResponseObj(resp))
		context.SetCtxData(JsonExpObjResponseHeaderInstance, newResponseHeaderObj(resp))
		if respFilter, ok := context.GetCtxData(ContextVarResponseFilter); ok && respFilter != nil {
			if err := respFilter.(*jsonexp.JsonExpGroup).Execute(context); err != nil {
				glog.Errorf("execute response filter fail for uri: %s", r.RequestURI)
				w.WriteHeader(500)
				return
			}
		}
		rewriteResponseUseContext(resp, context)
	}

	for _, plugin := range m.paddy.plugin {
		hijacked, resp, err = m.pluginResponseAdapter(plugin, resp, w, context)
		if err.Code != ErrCodeNoError {
			glog.Errorf("call plugin response: %s fail,%d, %s", plugin.ID(), err.Code, err.Error())
			w.WriteHeader(500)
			return
		}
		if hijacked {
			return
		}
	}

	if resp == nil {
		w.WriteHeader(404)
	} else {
		w.WriteHeader(resp.StatusCode)
		wHeader := w.Header()
		for k, v := range resp.Header {
			if len(v) > 0 {
				wHeader.Set(k, v[0])
			}
		}
		if _, err := io.Copy(w, resp.Body); err != nil {
			glog.Errorf("uri: %s, write response body fail, %s", r.RequestURI, err.Error())
		}
	}
}

// paddy web server
type Paddy struct {
	handler       *PaddyHandler
	jsonexpDict   *jsonexp.Dictionary
	fileServer    *FileServer
	backendGroups map[string]*BackendGroup
	backendDefs   map[string]*BackendDef
	vServers      []*VirtualServer
	configFile    string
	plugin        []Plugin
	ready         bool
}

func NewPaddy(configFile string) (*Paddy, goutil.Error) {
	ret := &Paddy{}
	ret.init()
	ret.configFile = configFile
	err := ret.loadConfig(configFile, true)
	if err.Code != ErrCodeNoError {
		return nil, err
	}
	return ret, ErrorNoError
}

func (m *Paddy) init() {
	m.fileServer = &FileServer{}
	m.handler = &PaddyHandler{paddy: m}
	m.jsonexpDict = jsonexp.NewDictionary()
	m.initJsonexpDict()
	m.backendGroups = make(map[string]*BackendGroup)
	m.backendDefs = make(map[string]*BackendDef)
	m.vServers = make([]*VirtualServer, 0)
	m.plugin = make([]Plugin, 0)
}

func (m *Paddy) initJsonexpDict() {
	m.jsonexpDict.RegisterVar(JsonExpVarBackend, nil)
	m.jsonexpDict.RegisterVar(JsonExpVarFileRoot, nil)
	m.jsonexpDict.RegisterVar(JsonExpVarSetResponse, nil)

	m.jsonexpDict.RegisterObject(JsonExpObjRequest, &RequestObj{})
	m.jsonexpDict.RegisterObject(JsonExpObjRequestHeader, &RequestHeaderObj{})
	m.jsonexpDict.RegisterObject(JsonExpObjRequestParam, &RequestParamObj{})
	m.jsonexpDict.RegisterObject(JsonExpObjResponse, &ResponseObj{})
	m.jsonexpDict.RegisterObject(JsonExpObjResponseHeader, &ResponseHeaderObj{})
}

func (m *Paddy) GetConfigFile() string {
	return m.configFile
}

func (m *Paddy) RegisterPlugin(plugin Plugin) goutil.Error {
	for _, v := range m.plugin {
		if v.ID() == plugin.ID() {
			return goutil.NewErrorf(ErrCodePluginDup, ErrMsgPluginDup, v.ID())
		}
	}
	m.plugin = append(m.plugin, plugin)
	return ErrorNoError
}

func (m *Paddy) findVServer(host string) *VirtualServer {
	for _, v := range m.vServers {
		if _, ok := v.hosts[host]; ok {
			return v
		}
	}
	return nil
}

func (m *Paddy) doLocation(r *http.Request, w http.ResponseWriter, context goutil.Context) (done bool, backend string, response *http.Response, err goutil.Error) {
	vSvr := m.findVServer(r.Host)
	if vSvr == nil {
		return false, "", nil, ErrorNoError
	}

	var reItem *RegexpLocationItem = nil
	if vSvr.regexpLocation != nil {
		for _, v := range vSvr.regexpLocation.Items {
			loc := v.uriRegexp.FindStringIndex(r.RequestURI)
			if loc != nil && loc[0] == 0 && loc[1] == len(r.RequestURI) {
				reItem = v
				break
			}
		}
		if reItem != nil {
			if reItem.requestFilter != nil {
				if err := reItem.requestFilter.Execute(context); err != nil {
					glog.Errorf("execute request filter fail for uri: %s", r.RequestURI)
					return false, "", nil, goutil.NewErrorf(ErrCodeJsonexpExecute, ErrMsgJsonexpExecute, err.Error())
				}
			}

			if i, ok := context.GetCtxData(JsonExpVarSetResponse); ok && goutil.GetIntValueDefault(i, 0) == 1 {
				if writeResponseUseContext(w, context) {
					return true, "", nil, ErrorNoError
				}
			}

			rewriteRequestUseContext(r, context)
			if reItem.responseFilter != nil {
				context.SetCtxData(ContextVarResponseFilter, reItem.responseFilter)
			}

			fileRoot := reItem.fileRoot
			if fileRoot == "" {
				if i, ok := context.GetCtxData(JsonExpVarFileRoot); ok {
					fileRoot = goutil.GetStringValue(i)
				}
			}

			if fileRoot != "" {
				done, err := m.fileServer.serve(fileRoot, r, w)
				if err.Code != ErrCodeNoError {
					return false, "", nil, err
				} else if done {
					return true, "", nil, ErrorNoError
				}
			}

			if i, ok := context.GetCtxData(JsonExpVarBackend); ok {
				if backend := goutil.GetStringValue(i); backend != "" {
					return false, backend, nil, ErrorNoError
				}
			}
		}
	}

	if vSvr.jsonexpLocation != nil && vSvr.jsonexpLocation.Exp != nil {
		if err := vSvr.jsonexpLocation.Exp.Execute(context); err != nil {
			glog.Errorf("execute Exp fail for uri: %s", r.RequestURI)
			return false, "", nil, goutil.NewErrorf(ErrCodeJsonexpExecute, ErrMsgJsonexpExecute, err.Error())
		}

		if vSvr.jsonexpLocation.requestFilter != nil {
			if err := vSvr.jsonexpLocation.requestFilter.Execute(context); err != nil {
				glog.Errorf("execute request filter fail for uri: %s", r.RequestURI)
				return false, "", nil, goutil.NewErrorf(ErrCodeJsonexpExecute, ErrMsgJsonexpExecute, err.Error())
			}
		}

		if i, ok := context.GetCtxData(JsonExpVarSetResponse); ok && goutil.GetIntValueDefault(i, 0) == 1 {
			if writeResponseUseContext(w, context) {
				return true, "", nil, ErrorNoError
			}
		}

		rewriteRequestUseContext(r, context)
		if vSvr.jsonexpLocation.responseFilter != nil {
			context.SetCtxData(ContextVarResponseFilter, vSvr.jsonexpLocation.responseFilter)
		}

		fileRoot := ""
		if i, ok := context.GetCtxData(JsonExpVarFileRoot); ok {
			fileRoot = goutil.GetStringValue(i)
		}

		if fileRoot != "" {
			done, err := m.fileServer.serve(fileRoot, r, w)
			if err.Code != ErrCodeNoError {
				return false, "", nil, err
			} else if done {
				return true, "", nil, ErrorNoError
			}
		}

		if i, ok := context.GetCtxData(JsonExpVarBackend); ok {
			if backend := goutil.GetStringValue(i); backend != "" {
				return false, backend, nil, ErrorNoError
			}
		}

	}

	return false, "", nil, ErrorNoError
}

func (m *Paddy) doBackend(backend string, r *http.Request, context goutil.Context) (response *http.Response, err goutil.Error) {
	backendObj, ok := m.backendDefs[backend]
	if !ok {
		return nil, goutil.NewErrorf(ErrCodeBackendNotFound, ErrMsgBackendNotFound, backend)
	}

	if resp, err := backendObj.lbClient.DoRequest(RemoteIp(r), r); err != nil {
		return nil, goutil.NewErrorf(ErrCodeBackendRequestFail, ErrMsgBackendRequestFail, backend, err.Error())
	} else {
		return resp, ErrorNoError
	}
}

func (m *Paddy) loadConfig(configFile string, rootCfg bool) goutil.Error {
	if !goutil.FileExists(m.configFile) {
		return goutil.NewErrorf(ErrCodeConfigNotExist, ErrMsgConfigNotExist, configFile)
	}
	bts, err := os.ReadFile(m.configFile)
	if err != nil {
		return goutil.NewErrorf(ErrCodeConfigReadFail, ErrMsgConfigReadFail, configFile, err.Error())
	}
	bts = []byte(TrimJsonComment(string(bts)))
	cfgMap := make(map[string]interface{})
	err = json.Unmarshal(bts, &cfgMap)
	if err != nil {
		return goutil.NewErrorf(ErrCodeConfigReadFail, ErrMsgConfigReadFail, configFile, err.Error())
	}

	// include
	if includeFiles, includeOk := cfgMap[CfgInclude]; includeOk {
		// load includeFiles
		rv := reflect.ValueOf(includeFiles)
		if rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgInclude)
		}
		for _, v := range includeFiles.([]interface{}) {
			vStr := goutil.GetStringValue(v)
			gErr := m.loadConfig(vStr, false)
			if gErr.Code != ErrCodeNoError {
				return gErr
			}
		}
	}

	// backend_group
	if backendGroup, bgOk := cfgMap[CfgBackendGroup]; bgOk {
		if rv := reflect.ValueOf(backendGroup); rv.Kind() != reflect.Map {
			return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgBackendGroup)
		}
		bgMap := backendGroup.(map[string]interface{})
		for grpName, v := range bgMap {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.Slice {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendGroup, grpName)
			}
			addrI := v.([]interface{})
			for _, v := range addrI {
				if rv := reflect.ValueOf(v); rv.Kind() != reflect.String {
					return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendGroup, grpName)
				}
				if gErr := m.newBackendGroup(grpName, v.([]string)); gErr.Code != ErrCodeNoError {
					return gErr
				}
			}
		}
	}

	// backend_def
	if backendDef, bdOk := cfgMap[CfgBackendDef]; bdOk {
		if rv := reflect.ValueOf(backendDef); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgBackendDef)
		}
		bdArr := backendDef.([]interface{})
		for _, v := range bdArr {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.Map {
				return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgBackendDef)
			}
			if gErr := m.newBackendDef(v.(map[string]interface{})); gErr.Code != ErrCodeNoError {
				return gErr
			}
		}
	}

	// server
	if server, ok := cfgMap[CfgServer]; ok {
		if rv := reflect.ValueOf(server); rv.Kind() != reflect.Map {
			return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgServer)
		}
		if gErr := m.newVirtualServer(server.(map[string]interface{})); gErr.Code != ErrCodeNoError {
			return gErr
		}
	}

	// append backend from backendGroup
	if rootCfg {
		for _, def := range m.backendDefs {
			for _, grpStr := range def.backendGroupList {
				if grp, ok := m.backendGroups[grpStr]; ok {
					for _, gBackend := range grp.BackendList {
						exists := false
						for _, backend := range def.BackendList {
							if backend.Ip == gBackend.Ip && backend.Port == gBackend.Port {
								exists = true
								break
							}
						}
						if !exists {
							def.BackendList = append(def.BackendList, gBackend)
						}
					}
				}
			}

		}
	}

	// create backend loadbalance client
	for _, v := range m.backendDefs {
		v.lbClient = lblhttpclient.NewLoadBalanceClient(
			MethodStrToI(v.Method),
			v.MaxIdleConn,
			v.ParamKey,
			time.Millisecond*time.Duration(DefaultBackendConnTimeout),
			v.WaitResponseTiemout,
		)
	}

	return ErrorNoError
}

func (m *Paddy) newVirtualServer(cfg map[string]interface{}) goutil.Error {
	if cfg == nil {
		return goutil.NewErrorf(ErrCodeNewServerFail, "cfg map is nil")
	}

	vs := &VirtualServer{}
	vs.init()
	// listen
	if listen, ok := cfg[CfgServerListen]; ok {
		if rv := reflect.ValueOf(listen); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerListen)
		}
		for _, v := range listen.([]interface{}) {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.String {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerListen)
			}
			lst := strings.Split(v.(string), ",")
			if len(lst) > 2 {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerListen)
			}
			port, err := strconv.Atoi(lst[0])
			if err != nil || port <= 0 || port >= int(math.MaxUint16) {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerListen)
			}
			for _, vs := range m.vServers {
				if _, ok := vs.listenPorts[uint16(port)]; ok {
					return goutil.NewErrorf(ErrCodeListenPortDup, ErrMsgListenPortDup, port)
				}
			}
			if _, ok := vs.listenPorts[uint16(port)]; ok {
				return goutil.NewErrorf(ErrCodeListenPortDup, ErrMsgListenPortDup, port)
			}

			if len(lst) == 2 {
				if lst[1] != "tls" && lst[1] != "ssl" {
					return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerListen)
				}
				vs.listenPorts[uint16(port)] = true
			} else {
				vs.listenPorts[uint16(port)] = false
			}
		}
	}

	// hosts
	if hosts, ok := cfg[CfgServerHosts]; ok {
		if rv := reflect.ValueOf(hosts); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerHosts)
		}
		for _, v := range hosts.([]interface{}) {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.String || v.(string) == "" {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerHosts)
			}
			vStr := v.(string)
			if _, ok := vs.hosts[vStr]; ok {
				return goutil.NewErrorf(ErrCodeHostDup, ErrMsgHostDup, v)
			}
			for _, vs := range m.vServers {
				if _, ok := vs.hosts[vStr]; ok {
					return goutil.NewErrorf(ErrCodeHostDup, ErrMsgHostDup, v)
				}
			}
			vs.hosts[vStr] = nil
		}
	}

	// tls_cert
	if cert, ok := cfg[CfgServerTlsCert]; ok {
		if rv := reflect.ValueOf(cert); rv.Kind() != reflect.String || cert.(string) == "" {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerTlsCert)
		}
		if !goutil.FileExists(cert.(string)) {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerTlsCert)
		}
		vs.tlsCert = cert.(string)
	}

	// tls_certkey
	if cert, ok := cfg[CfgServerTlsCertKey]; ok {
		if rv := reflect.ValueOf(cert); rv.Kind() != reflect.String || cert.(string) == "" {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerTlsCertKey)
		}
		if !goutil.FileExists(cert.(string)) {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerTlsCertKey)
		}
		vs.tlsCertKey = cert.(string)
	}

	// location_regexp
	if rex, ok := cfg[CfgServerLocationRegexp]; ok {
		if rv := reflect.ValueOf(rex); rv.Kind() != reflect.Map {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerLocationRegexp)
		}
		rexMap := rex.(map[string]interface{})
		for k, v := range rexMap {
			item := &RegexpLocationItem{}
			if k == CfgServerLocationRegexpExp {
				vStr := goutil.GetStringValue(v)
				if vStr == "" {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationRegexp, CfgServerLocationRegexpExp)
				}
				if reObj, err := regexp.Compile(vStr); err != nil {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationRegexp, CfgServerLocationRegexpExp)
				} else {
					item.uriRegexp = reObj
				}
			} else if k == CfgServerLocationRegexpFileRoot {
				vStr := goutil.GetStringValue(v)
				if vStr == "" {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationRegexp, CfgServerLocationRegexpFileRoot)
				}
				item.fileRoot = vStr
			} else if k == CfgServerLocationRegexpBackend {
				vStr := goutil.GetStringValue(v)
				if vStr == "" {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationRegexp, CfgServerLocationRegexpBackend)
				}
				item.backend = vStr
			} else if k == CfgServerLocationRegexpRequestFilter {
				if expObj, err := jsonexp.NewJsonExpGroup(m.jsonexpDict, v); err != nil {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationRegexp, CfgServerLocationRegexpRequestFilter)
				} else {
					item.requestFilter = expObj
				}
			} else if k == CfgServerLocationRegexpResponseFilter {
				if expObj, err := jsonexp.NewJsonExpGroup(m.jsonexpDict, v); err != nil {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationRegexp, CfgServerLocationRegexpResponseFilter)
				} else {
					item.responseFilter = expObj
				}
			}
			if vs.regexpLocation == nil {
				vs.regexpLocation = &RegexpLocation{}
			}
			vs.regexpLocation.Items = append(vs.regexpLocation.Items, item)
		}
	}

	// location_jsonexp
	if jex, ok := cfg[CfgServerLocationJsonexp]; ok {
		if rv := reflect.ValueOf(jex); rv.Kind() != reflect.Map {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerLocationJsonexp)
		}
		vs.jsonexpLocation = &JsonexpLocation{}
		jexMap := jex.(map[string]interface{})
		for k, v := range jexMap {
			if k == CfgServerLocationJsonexpExp {
				if obj, err := jsonexp.NewJsonExpGroup(m.jsonexpDict, v); err != nil {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationJsonexp, CfgServerLocationJsonexpExp)
				} else {
					vs.jsonexpLocation.Exp = obj
				}
			} else if k == CfgServerLocationJsonexpRequestFilter {
				if obj, err := jsonexp.NewJsonExpGroup(m.jsonexpDict, v); err != nil {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationJsonexp, CfgServerLocationJsonexpRequestFilter)
				} else {
					vs.jsonexpLocation.requestFilter = obj
				}
			} else if k == CfgServerLocationJsonexpResponseFilter {
				if obj, err := jsonexp.NewJsonExpGroup(m.jsonexpDict, v); err != nil {
					return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationJsonexp, CfgServerLocationJsonexpResponseFilter)
				} else {
					vs.jsonexpLocation.responseFilter = obj
				}
			}
		}
	}

	m.vServers = append(m.vServers, vs)
	return ErrorNoError
}

func (m *Paddy) newBackendDef(cfg map[string]interface{}) goutil.Error {
	if cfg == nil {
		return goutil.NewErrorf(ErrCodeNewBackendDefFail, "cfg map is nil")
	}
	def := BackendDef{MaxIdleConn: DefaultBackendMaxIdleConn, WaitResponseTiemout: time.Duration(DefaultBackendWaitResponseTimeout) * time.Millisecond}
	// alias
	if alias, ok := cfg[CfgBackendDefAlias]; ok {
		if aliasStr, ok := alias.(string); ok {
			def.Alias = aliasStr
		}
	}

	// group_list
	if gl, ok := cfg[CfgBackendDefGroupList]; ok {
		if rv := reflect.ValueOf(gl); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefGroupList)
		}
		for _, v := range gl.([]interface{}) {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.String {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefGroupList)
			}
			def.backendGroupList = append(def.backendGroupList, v.(string))
		}
	}

	// backend_list
	if bl, ok := cfg[CfgBackendDefBackendList]; ok {
		if rv := reflect.ValueOf(bl); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendList)
		}
		for _, v := range bl.([]interface{}) {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.String {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendList)
			}
			backend, err := m.newBackend(v.(string))
			if err.Code != ErrCodeNoError {
				return err
			}
			def.BackendList = append(def.BackendList, *backend)
		}
	}

	// method
	if method, ok := cfg[CfgBackendDefBackendMethend]; ok {
		if rv := reflect.ValueOf(method); rv.Kind() != reflect.String {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendMethend)
		}
		methodStr := method.(string)
		methodOk := false
		for _, v := range AllMethods {
			if v == methodStr {
				methodOk = true
				break
			}
		}
		if !methodOk {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendMethend)
		}
		def.Method = methodStr
	}

	// param_key
	if pk, ok := cfg[CfgBackendDefBackendMethend]; ok {
		if rv := reflect.ValueOf(pk); rv.Kind() != reflect.String || pk.(string) == "" {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendParamkey)
		}
		def.ParamKey = pk.(string)
	}

	// jsonexp
	if je, ok := cfg[CfgBackendDefJsonexp]; ok {
		jeGrp, err := jsonexp.NewJsonExpGroup(m.jsonexpDict, je)
		if err != nil {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefJsonexp)
		}
		def.JsonExp = jeGrp
	}

	// max_idle_conn
	if conns, ok := cfg[CfgBackendDefMaxIdleConn]; ok {
		if i, ok := goutil.GetIntValue(conns); ok {
			if i > 0 {
				def.MaxIdleConn = int(i)
			}
		}
	}

	// wait_response_timeout
	if timeout, ok := cfg[CfgBackendDefMaxIdleConn]; ok {
		if i, ok := goutil.GetIntValue(timeout); ok {
			if i > 0 {
				def.WaitResponseTiemout = time.Duration(i) * time.Millisecond
			}
		}
	}

	if def.Alias != "" && len(def.BackendList) > 0 && def.Method != "" {
		if def.Method == MethodUrlParam && def.ParamKey == "" {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendParamkey)
		}
		if def.Method == MethodJsonExp && def.JsonExp == nil {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, CfgBackendDef, CfgBackendDefJsonexp)
		}
		if _, ok := m.backendDefs[def.Alias]; ok {
			return goutil.NewErrorf(ErrCodeBackendDefDup, ErrMsgBackendDefDup, def.Alias)
		}
		m.backendDefs[def.Alias] = &def
	}

	return ErrorNoError
}

func (m *Paddy) newBackend(addrStr string) (*Backend, goutil.Error) {
	v := addrStr

	list := strings.Split(v, ":")
	if len(list) != 2 || len(list[0]) == 0 || len(list[1]) == 0 {
		return nil, goutil.NewErrorf(ErrCodeNewBackendGroupFail, "invalid addr")
	}
	ip := list[0]
	list = strings.Split(list[1], "#")
	if len(list) > 2 || len(list[0]) == 0 {
		return nil, goutil.NewErrorf(ErrCodeNewBackendGroupFail, "invalid addr")
	}
	portInt, err := strconv.Atoi(list[0])
	if err != nil {
		return nil, goutil.NewErrorf(ErrCodeNewBackendGroupFail, "invalid addr")
	}
	if portInt <= 0 || portInt >= int(math.MaxUint16) {
		return nil, goutil.NewErrorf(ErrCodeNewBackendGroupFail, "invalid addr")
	}
	weightInt, err := strconv.Atoi(list[1])
	if err != nil {
		return nil, goutil.NewErrorf(ErrCodeNewBackendGroupFail, "invalid addr")
	}
	if weightInt < 1 || weightInt > 100 {
		return nil, goutil.NewErrorf(ErrCodeNewBackendGroupFail, "invalid addr")
	}
	return &Backend{Ip: ip, Port: uint16(portInt), Weight: weightInt}, ErrorNoError
}

func (m *Paddy) newBackendGroup(groupName string, addrList []string) goutil.Error {
	if groupName == "" {
		return goutil.NewErrorf(ErrCodeNewBackendGroupFail, "groupName is empty")
	}
	if len(addrList) == 0 {
		return goutil.NewErrorf(ErrCodeNewBackendGroupFail, "addrList is empty")
	}
	var backends []Backend
	for _, v := range addrList {
		if backend, err := m.newBackend(v); err.Code != ErrCodeNoError {
			return err
		} else {
			backends = append(backends, *backend)
		}
	}
	if _, ok := m.backendGroups[groupName]; ok {
		return goutil.NewErrorf(ErrCodeBackendGroupDup, ErrMsgBackendGroupDup, groupName)
	}
	m.backendGroups[groupName] = &BackendGroup{Name: groupName, BackendList: backends}

	return goutil.NewError(ErrCodeNoError, "")
}

//envVarValue fd:port,fd:port,fd:port,...
func (m *Paddy) GenerateInheritedPortsEnv(beginFd uintptr, originPaddy *Paddy) (noCloseFds []*os.File, envVarValue string) {
	var ret []int
	ports := make(map[uint16]bool)
	for _, vs := range m.vServers {
		for k, v := range vs.listenPorts {
			ports[k] = v
		}
	}
	for _, ovs := range originPaddy.vServers {
		for _, v := range ovs.listeners {
			if _, ok := ports[v.port]; ok {
				ret = append(ret, int(v.port))
			}
		}
	}

	sort.Ints(ret)
	curFd := beginFd
	for _, portInt := range ret {
		for _, ovs := range originPaddy.vServers {
			for _, lsn := range ovs.listeners {
				if int(lsn.port) == portInt {
					if f, err := lsn.tcpListener.File(); err == nil {
						noCloseFds = append(noCloseFds, f)
						if envVarValue != "" {
							envVarValue += ","
						}
						envVarValue += fmt.Sprintf("%d:%d", curFd, portInt)
						curFd++
					}
				}
			}
		}
	}

	return noCloseFds, envVarValue
}

func (m *Paddy) GetInheritedPortsFromEnv(envVar string) (inheritedFds []uintptr, inheritedPorts []uint16) {
	varStr, found := os.LookupEnv(envVar)
	if !found {
		return nil, nil
	}
	list := strings.Split(varStr, ",")
	for _, v := range list {
		lst := strings.Split(v, ":")
		if len(lst) != 2 {
			continue
		}
		fd, err := strconv.Atoi(lst[0])
		if err != nil {
			panic(err)
		}
		port, err := strconv.Atoi(lst[1])
		if err != nil {
			panic(err)
		}
		inheritedFds = append(inheritedFds, uintptr(fd))
		inheritedPorts = append(inheritedPorts, uint16(port))
	}

	return inheritedFds, inheritedPorts
}

func newInheritedListener(fd uintptr) (*net.TCPListener, error) {
	f := os.NewFile(fd, fmt.Sprintf("listener%d", fd))
	l, err := net.FileListener(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return l.(*net.TCPListener), nil
}

func (m *Paddy) StartListen() goutil.Error {
	inheritedPortsEnvVar := EnvVarInheritedListener
	inheritedFds, inheritedPorts := m.GetInheritedPortsFromEnv(inheritedPortsEnvVar)
	findInheritedListener := func(port uint16) *net.TCPListener {
		for i, v := range inheritedPorts {
			if port == v {
				lsn, _ := newInheritedListener(inheritedFds[i])
				return lsn
			}
		}
		return nil
	}

	for _, vs := range m.vServers {
		for port, isTls := range vs.listenPorts {
			lsn := findInheritedListener(port)
			if lsn == nil {
				tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%d", port))
				if err != nil {
					return goutil.NewError(ErrCodeListenFail, err.Error())
				}
				lsn, err = net.ListenTCP("tcp4", tcpAddr)
				if err != nil {
					return goutil.NewError(ErrCodeListenFail, err.Error())
				}
			}
			paddyListener := &Listener{port: port, tcpListener: lsn, tls: isTls}
			paddyListener.httpServer = &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: m.handler}
			vs.listeners[port] = paddyListener
			if isTls {
				go func() {
					if err := paddyListener.httpServer.ServeTLS(lsn, vs.tlsCert, vs.tlsCertKey); err != nil {
						panic(err)
					}
				}()
			} else {
				go func() {
					if err := paddyListener.httpServer.Serve(lsn); err != nil {
						panic(err)
					}
				}()
			}
		}
	}

	m.ready = true
	return goutil.NewError(ErrCodeNoError, "")
}
