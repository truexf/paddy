// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
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

	// 收到请求后介入
	// hijacked 是否劫持：true则必须实现respWriter写响应；false时不准向respWriter写响应，可以返回backend(此时框架直接去请求backend而不再走location匹配流程，否则框架执行location匹配)
	RequestHeaderCompleted(req *http.Request, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, proxyPass, backend string, err goutil.Error)

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
	MaxIdleConn         int
	WaitResponseTiemout time.Duration
	lbClient            *lblhttpclient.LblHttpClient
}

func (m *BackendDef) createLbClient() {
	m.lbClient = lblhttpclient.NewLoadBalanceClient(
		MethodStrToI(m.Method),
		m.MaxIdleConn,
		m.ParamKey,
		time.Millisecond*time.Duration(DefaultBackendConnTimeout),
		m.WaitResponseTiemout,
	)
	for _, v := range m.BackendList {
		for i := 0; i < v.Weight; i++ {
			m.lbClient.AddBackend(fmt.Sprintf("%s:%d", v.Ip, v.Port), fmt.Sprintf("%s:%d:%d", v.Ip, v.Port, i), nil)
		}
	}
}

type RegexpLocationItem struct {
	uriRegexp      *regexp.Regexp
	backend        string
	fileRoot       string
	proxyPass      string
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
}

func (m *VirtualServer) init() {
	m.listenPorts = make(map[uint16]bool)
	m.hosts = make(map[string][]byte)
}

// tcp server
type TcpServer struct {
	paddy       *Paddy
	ready       bool
	listeners   map[uint16]*net.TCPListener
	upstream    string
	upstreamObj *TcpLbClient
}

func (m *TcpServer) startListen() error {
	inheritedPortsEnvVar := EnvVarInheritedListenerTcp
	inheritedFds, inheritedPorts := m.paddy.GetInheritedPortsFromEnv(inheritedPortsEnvVar)
	findInheritedListener := func(port uint16) (*net.TCPListener, bool) {
		for i, v := range inheritedPorts {
			if port == v {
				lsn, _ := newInheritedListener(inheritedFds[i])
				return lsn, true
			}
		}
		return nil, false
	}

	mp := make(map[uint16]*net.TCPListener)
	for port := range m.listeners {
		var err error
		var lsn net.Listener
		found := false
		lsn, found = findInheritedListener(port)
		if !found {
			lsn, err = net.Listen("tcp4", fmt.Sprintf(":%d", port))
			if err != nil {
				return err
			}
		}
		mp[port] = lsn.(*net.TCPListener)
	}

	m.listeners = mp
	for port, lsn := range mp {
		m.serve(port, lsn)
	}

	m.ready = true
	return nil
}

func (m *TcpServer) serve(port uint16, listener *net.TCPListener) {
	go func() {
		for {
			if clientConn, err := m.acceptConn(port, listener); err != nil {
				glog.Errorf("accept connection fail, %s", err.Error())
				return
			} else {
				clientAddr := clientConn.RemoteAddr().String()
				backendConn, err := m.upstreamObj.ConnectBackend(clientAddr)
				if err != nil {
					glog.Errorf("connect upstream: %s fail, %s", m.upstream, err.Error())
					clientConn.Close()
				}
				backAddr := backendConn.RemoteAddr().String()
				// client => backend
				go func(client, backend *net.TCPConn) {
					if _, err := io.Copy(backend, client); err != nil {
						glog.Errorf("client %s => backend %s, connection closed unnormal, %s", clientAddr, backAddr, err.Error())
					}
					clientConn.Close()
					backendConn.Close()
					m.upstreamObj.removeConn(clientAddr)

				}(clientConn, backendConn)
				// backend => client
				go func(client, backend *net.TCPConn) {
					if _, err := io.Copy(client, backend); err != nil {
						glog.Errorf("backend %s => client %s, connection closed unnormal, %s", backAddr, clientAddr, err.Error())
					}
					clientConn.Close()
					backendConn.Close()
					m.upstreamObj.removeConn(clientAddr)
				}(clientConn, backendConn)
			}
		}
	}()
}

func (m *TcpServer) acceptConn(port uint16, listener *net.TCPListener) (*net.TCPConn, error) {
	for {
		netConn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				time.Sleep(time.Second)
				continue
			} else {
				return nil, err
			}
		}
		glog.Infof("listen port %d, accepted new connection: %s", port, netConn.RemoteAddr().String())
		return netConn.(*net.TCPConn), nil
	}
}

type PaddyHandler struct {
	paddy *Paddy
}

func (m *PaddyHandler) pluginRequestAdapter(plugin Plugin, req *http.Request, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, proxyPass string, backend string, err goutil.Error) {
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

type Upstream struct {
	alias       string
	method      string
	backendList []string
	connTimeout time.Duration
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
	var proxyPass string
	var err goutil.Error
	var resp *http.Response

	for _, plugin := range m.paddy.plugin {
		hijacked, proxyPass, backend, err = m.pluginRequestAdapter(plugin, r, w, context)
		if err.Code != ErrCodeNoError {
			glog.Errorf("call plugin request: %s fail,%d, %s", plugin.ID(), err.Code, err.Error())
			w.WriteHeader(500)
			return
		}
		if hijacked {
			return
		}
		if backend != "" || proxyPass != "" {
			break
		}
	}

	resp = &http.Response{StatusCode: 404}
	m.paddy.jsonexpDict.RegisterObjectInContext(JsonExpObjRequestInstance, newRequestObj(r), context)
	m.paddy.jsonexpDict.RegisterObjectInContext(JsonExpObjRequestHeaderInstance, newRequestHeaderObj(r), context)
	m.paddy.jsonexpDict.RegisterObjectInContext(JsonExpObjRequestParamInstance, newRequestParamObj(r), context)

	m.paddy.jsonexpDict.RegisterObjectInContext(JsonExpObjResponseInstance, newResponseObj(resp), context)
	m.paddy.jsonexpDict.RegisterObjectInContext(JsonExpObjResponseHeaderInstance, newResponseHeaderObj(resp), context)

	doLoop := true
	for {
		// only onece
		if !doLoop {
			break
		} else {
			doLoop = !doLoop
		}

		if backend == "" {
			var response *http.Response
			done, proxyPass, backend, response, err = m.paddy.doLocation(r, w, context)
			if response != nil {
				resp = response
			}
			if err.Code != ErrCodeNoError {
				glog.Errorf("uri: %s, do location fail, %d, %s", r.RequestURI, err.Code, err.Error())
				break
			}
			if done {
				return
			}

			if backend == "" && proxyPass == "" {
				break
			}
		}

		if !done && (backend != "" || proxyPass != "") {
			resp, err = m.paddy.doBackend(proxyPass, backend, r, context)
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
		if resp.Body != nil {
			if _, err := io.Copy(w, resp.Body); err != nil {
				glog.Errorf("uri: %s, write response body fail, %s", r.RequestURI, err.Error())
			}
		}
	}
}

// paddy web server
type Paddy struct {
	pidFile               string
	noneBackendHttpClient *http.Client
	handler               *PaddyHandler
	jsonexpDict           *jsonexp.Dictionary
	fileServer            *FileServer
	upstreams             map[string]*Upstream
	tcpServers            []*TcpServer //map[port]*TcpServer
	backendGroups         map[string]*BackendGroup
	backendDefs           map[string]*BackendDef
	listeners             map[uint16]*Listener
	vServers              map[uint16]map[string]*VirtualServer // map[port]map[host]*VirtualServer
	configFile            string
	plugin                []Plugin
	ready                 bool
}

func NewPaddy(configFile string) (*Paddy, goutil.Error) {
	ret := &Paddy{}
	ret.init()
	ret.configFile = configFile
	loadedMap := make(map[string]bool)
	err := ret.loadConfig(configFile, true, loadedMap)
	if err.Code != ErrCodeNoError {
		return nil, err
	}
	return ret, ErrorNoError
}

func (m *Paddy) init() {
	m.noneBackendHttpClient = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   time.Duration(DefaultBackendConnTimeout) * time.Millisecond,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2: true,
			// MaxIdleConns:          maxIdleConns,
			MaxIdleConnsPerHost:   DefaultBackendMaxIdleConn,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: time.Duration(DefaultBackendWaitResponseTimeout) * time.Millisecond,
		},
	}
	m.fileServer = NewFileServer(10 << 30)
	m.handler = &PaddyHandler{paddy: m}
	m.jsonexpDict = jsonexp.NewDictionary()
	m.initJsonexpDict()
	m.backendGroups = make(map[string]*BackendGroup)
	m.backendDefs = make(map[string]*BackendDef)
	m.listeners = make(map[uint16]*Listener)
	m.vServers = make(map[uint16]map[string]*VirtualServer)
	m.plugin = make([]Plugin, 0)
	m.tcpServers = make([]*TcpServer, 0)
	m.upstreams = make(map[string]*Upstream)
}

func (m *Paddy) initJsonexpDict() {
	m.jsonexpDict.RegisterVar(JsonExpVarProxyPass, nil)
	m.jsonexpDict.RegisterVar(JsonExpVarBackend, nil)
	m.jsonexpDict.RegisterVar(JsonExpVarFileRoot, nil)
	m.jsonexpDict.RegisterVar(JsonExpVarSetResponse, nil)
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
	host = strings.ToLower(host)
	var port uint16 = 80
	lst := strings.Split(host, ":")
	if len(lst) > 1 {
		i, err := strconv.Atoi(lst[1])
		if err == nil && i >= 0 && i < math.MaxUint16 {
			port = uint16(i)
		}
	}
	if svrList, ok := m.vServers[port]; ok {
		for _, v := range svrList {
			if _, ok := v.hosts[lst[0]]; ok {
				return v
			}
		}
	}

	return nil
}

func (m *Paddy) doLocation(r *http.Request, w http.ResponseWriter, context goutil.Context) (done bool, proxyPass string, backend string, response *http.Response, err goutil.Error) {
	vSvr := m.findVServer(r.Host)
	if vSvr == nil {
		return false, "", "", nil, ErrorNoError
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
					return false, "", "", nil, goutil.NewErrorf(ErrCodeJsonexpExecute, ErrMsgJsonexpExecute, err.Error())
				}
			}

			if i, ok := context.GetCtxData(JsonExpVarSetResponse); ok && goutil.GetIntValueDefault(i, 0) == 1 {
				if writeResponseUseContext(w, context) {
					return true, "", "", nil, ErrorNoError
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
					return false, "", "", nil, err
				} else if done {
					return true, "", "", nil, ErrorNoError
				}
			}

			proxyPass := reItem.proxyPass
			if proxyPass == "" {
				if i, ok := context.GetCtxData(JsonExpVarProxyPass); ok {
					proxyPass = goutil.GetStringValue(i)
				}
			}

			backend := reItem.backend
			if backend == "" {
				if i, ok := context.GetCtxData(JsonExpVarBackend); ok {
					backend = goutil.GetStringValue(i)
				}
			}
			return false, proxyPass, backend, nil, ErrorNoError
		}
	}

	if vSvr.jsonexpLocation != nil && vSvr.jsonexpLocation.Exp != nil {
		if err := vSvr.jsonexpLocation.Exp.Execute(context); err != nil {
			glog.Errorf("execute Exp fail for uri: %s", r.RequestURI)
			return false, "", "", nil, goutil.NewErrorf(ErrCodeJsonexpExecute, ErrMsgJsonexpExecute, err.Error())
		}

		if vSvr.jsonexpLocation.requestFilter != nil {
			if err := vSvr.jsonexpLocation.requestFilter.Execute(context); err != nil {
				glog.Errorf("execute request filter fail for uri: %s", r.RequestURI)
				return false, "", "", nil, goutil.NewErrorf(ErrCodeJsonexpExecute, ErrMsgJsonexpExecute, err.Error())
			}
		}

		if i, ok := context.GetCtxData(JsonExpVarSetResponse); ok && goutil.GetIntValueDefault(i, 0) == 1 {
			if writeResponseUseContext(w, context) {
				return true, "", "", nil, ErrorNoError
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
				return false, "", "", nil, err
			} else if done {
				return true, "", "", nil, ErrorNoError
			}
		}

		proxyPass := ""
		if i, ok := context.GetCtxData(JsonExpVarProxyPass); ok {
			proxyPass = goutil.GetStringValue(i)
		}

		backend := ""
		if i, ok := context.GetCtxData(JsonExpVarBackend); ok {
			backend = goutil.GetStringValue(i)
		}

		return false, proxyPass, backend, nil, ErrorNoError

	}

	return false, "", "", nil, ErrorNoError
}

func (m *Paddy) doBackend(proxyPass string, backend string, r *http.Request, context goutil.Context) (response *http.Response, e goutil.Error) {
	if proxyPass == "" && backend == "" {
		return nil, goutil.NewErrorf(ErrCodeBackendRequestFail, ErrMsgBackendRequestFail, "", "no backend no proxy")
	}

	var err error
	var resp *http.Response
	var noneBackend bool
	var backendObj *BackendDef

	if backend != "" {
		ok := false
		backendObj, ok = m.backendDefs[backend]
		if !ok {
			return nil, goutil.NewErrorf(ErrCodeBackendNotFound, ErrMsgBackendNotFound, backend)
		}
	}

	if proxyPass != "" {
		noneBackend = true
		proxyPass = strings.ReplaceAll(proxyPass, MacroBackend, backend)
		domain := ""
		port := "80"
		hostsParts := strings.Split(r.Host, ":")
		if len(hostsParts) > 1 {
			domain = hostsParts[0]
			port = hostsParts[1]
		}
		proxyPass = strings.ReplaceAll(proxyPass, MacroHost, r.Host)
		proxyPass = strings.ReplaceAll(proxyPass, MacroDomain, domain)
		proxyPass = strings.ReplaceAll(proxyPass, MacroPort, port)
		proxyPass = strings.ReplaceAll(proxyPass, MacroPath, r.URL.Path)
		proxyPass = strings.ReplaceAll(proxyPass, MacroParams, r.URL.Query().Encode())
		proxyPass = strings.ReplaceAll(proxyPass, MacroURI, r.URL.RequestURI())
		if len(proxyPass) < len("http") || !strings.EqualFold(proxyPass[:len("http")], "http") {
			proxyPass = "http://" + proxyPass
		}
		if reqTemp, err := http.NewRequest(r.Method, proxyPass, nil); err != nil {
			return nil, goutil.NewErrorf(ErrCodeBackendRequestFail, ErrMsgBackendRequestFail, backend, err.Error())
		} else {
			if reqTemp.Host == backend {
				noneBackend = false
			}
			reqTemp.Body = r.Body
			reqTemp.Header = r.Header
			*r = *reqTemp
		}
	} else {
		if reqTemp, err := http.NewRequest(r.Method, "http://backend"+r.RequestURI, nil); err != nil {
			return nil, goutil.NewErrorf(ErrCodeBackendRequestFail, ErrMsgBackendRequestFail, backend, err.Error())
		} else {
			noneBackend = false
			reqTemp.Body = r.Body
			reqTemp.Header = r.Header
			*r = *reqTemp
		}
	}

	remoteIP := RemoteIp(r)
	r.Header.Set("X-Forwarded-For", remoteIP)
	if noneBackend {
		resp, err = m.noneBackendHttpClient.Do(r)
	} else {
		resp, err = backendObj.lbClient.DoRequest(remoteIP, r)
	}

	if err != nil {
		return nil, goutil.NewErrorf(ErrCodeBackendRequestFail, ErrMsgBackendRequestFail, backend, err.Error())
	} else {
		return resp, ErrorNoError
	}
}

func (m *Paddy) loadConfig(configFile string, rootCfg bool, loadedMap map[string]bool) goutil.Error {
	if ok := loadedMap[configFile]; ok {
		return goutil.NewError(ErrCodeCommonError, "circular config "+configFile)
	}
	loadedMap[configFile] = true
	if !goutil.FileExists(configFile) {
		return goutil.NewErrorf(ErrCodeConfigNotExist, ErrMsgConfigNotExist, configFile)
	}
	bts, err := os.ReadFile(configFile)
	if err != nil {
		return goutil.NewErrorf(ErrCodeConfigReadFail, ErrMsgConfigReadFail, configFile, err.Error())
	}
	bts = []byte(TrimJsonComment(string(bts)))
	cfgMap := make(map[string]interface{})
	err = json.Unmarshal(bts, &cfgMap)
	if err != nil {
		return goutil.NewErrorf(ErrCodeConfigReadFail, ErrMsgConfigReadFail, configFile, err.Error())
	}

	// pid file
	if pidFile, ok := cfgMap[CfgPidFile]; ok {
		s := goutil.GetStringValue(pidFile)
		if m.pidFile, err = filepath.Abs(s); err != nil {
			return goutil.NewErrorf(ErrCodeConfigReadFail, ErrMsgConfigReadFail, configFile, "invalid pid_file")
		}
	}

	// include
	if includeFiles, includeOk := cfgMap[CfgInclude]; includeOk {
		// load includeFiles
		rv := reflect.ValueOf(includeFiles)
		if rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgInclude)
		}
		files := includeFiles.([]interface{})
		for _, v := range files {
			vStr := goutil.GetStringValue(v)
			gErr := m.loadConfig(vStr, false, loadedMap)
			if gErr.Code != ErrCodeNoError {
				return gErr
			}
		}
	}

	// upstream
	if upstream, ok := cfgMap[CfgUpstream]; ok {
		if rv := reflect.ValueOf(upstream); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgUpstream)
		}
		list := upstream.([]interface{})
		for _, v := range list {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.Map {
				return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgUpstream)
			}
			obj := v.(map[string]interface{})
			if gErr := m.newUpstream(obj); gErr.Code != ErrCodeNoError {
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
			if gErr := m.newBackendGroup(grpName, addrI); gErr.Code != ErrCodeNoError {
				return gErr
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

	// tcp_server
	if server, ok := cfgMap[CfgTcpServer]; ok {
		if rv := reflect.ValueOf(server); rv.Kind() != reflect.Map {
			return goutil.NewErrorf(ErrCodeCfgItemInvalid, ErrMsgCfgItemInvalid, CfgTcpServer)
		}
		if gErr := m.newTcpServer(server.(map[string]interface{})); gErr.Code != ErrCodeNoError {
			return gErr
		}
	}

	// net tcp_server.tcpLbClient & validate port duplicate
	if rootCfg {
		for _, v := range m.tcpServers {
			for port := range v.listeners {
				for httpPort := range m.vServers {
					if httpPort == port {
						return goutil.NewErrorf(ErrCodeListenPortDup, ErrMsgListenPortDup, port)
					}
				}
			}
			if us, ok := m.upstreams[v.upstream]; !ok {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgTcpServer, CfgTcpServerUpstream)
			} else {
				if o, err := newTcpLbClient(us.backendList, us.method, us.connTimeout); err != nil {
					return goutil.NewErrorf(ErrCodeNewUpstream, ErrMsgNewUpstream, err.Error())
				} else {
					v.upstreamObj = o
				}
			}
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
		for k, def := range m.backendDefs {
			if len(def.BackendList) == 0 {
				delete(m.backendDefs, k)
			}
		}
	}

	// create backend loadbalance client
	if rootCfg {
		for _, v := range m.backendDefs {
			v.createLbClient()
		}
	}

	return ErrorNoError
}

func (m *Paddy) newTcpServer(cfg map[string]interface{}) goutil.Error {
	if cfg == nil {
		return goutil.NewErrorf(ErrCodeNewTcpServerFail, "cfg map is nil")
	}

	svr := &TcpServer{paddy: m, listeners: make(map[uint16]*net.TCPListener)}
	if listen, ok := cfg[CfgTcpServerListen]; ok {
		if rv := reflect.ValueOf(listen); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgTcpServer, CfgTcpServerListen)
		}
		for _, v := range listen.([]interface{}) {
			port := goutil.GetIntValueDefault(v, 0)
			if port <= 0 || port >= int64(math.MaxUint16) {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgTcpServer, CfgTcpServerListen)
			}
			if _, ok := svr.listeners[uint16(port)]; ok {
				return goutil.NewErrorf(ErrCodeListenPortDup, ErrMsgListenPortDup, port)
			}
			for _, ts := range m.tcpServers {
				if _, ok := ts.listeners[uint16(port)]; ok {
					return goutil.NewErrorf(ErrCodeListenPortDup, ErrMsgListenPortDup, port)
				}
			}
			svr.listeners[uint16(port)] = nil
		}
	}
	if upstream, ok := cfg["upstream"]; ok {
		svr.upstream = goutil.GetStringValue(upstream)
	}
	if svr.upstream != "" && len(svr.listeners) > 0 {
		m.tcpServers = append(m.tcpServers, svr)
	}

	return ErrorNoError

}

func (m *Paddy) newVirtualServer(cfg map[string]interface{}) goutil.Error {
	if cfg == nil {
		return goutil.NewErrorf(ErrCodeNewTcpServerFail, "cfg map is nil")
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
		if rv := reflect.ValueOf(rex); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerLocationRegexp)
		}
		rexSlice := rex.([]interface{})
		for _, vItem := range rexSlice {
			if rv := reflect.ValueOf(vItem); rv.Kind() != reflect.Map {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgServer, CfgServerLocationRegexp)
			}
			item := &RegexpLocationItem{}
			vMap := vItem.(map[string]interface{})
			for k, v := range vMap {
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
				} else if k == CfgServerLocationRegexpProxyPass {
					vStr := goutil.GetStringValue(v)
					if vStr == "" {
						return goutil.NewErrorf(ErrCodeCfgItem3Invalid, ErrMsgCfgItem3Invalid, CfgServer, CfgServerLocationRegexp, CfgServerLocationRegexpProxyPass)
					}
					item.proxyPass = vStr
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
			}
			if item.uriRegexp != nil {
				if vs.regexpLocation == nil {
					vs.regexpLocation = &RegexpLocation{}
				}
				vs.regexpLocation.Items = append(vs.regexpLocation.Items, item)
			}
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

	// validate port
	for k, v := range vs.listenPorts {
		if lsn, ok := m.listeners[k]; ok {
			if lsn.tls != v {
				return goutil.NewErrorf(ErrCodeNewServerFail, ErrMsgNewServerFail, fmt.Sprintf("listen port %d duplicated", k))
			}
		} else {
			m.listeners[k] = &Listener{port: k, tls: v}
		}
	}

	for k := range vs.listenPorts {
		samePortSvrs, ok := m.vServers[k]
		if !ok {
			samePortSvrs = make(map[string]*VirtualServer)
			m.vServers[k] = samePortSvrs
		}
		for host := range vs.hosts {
			if _, exists := samePortSvrs[host]; !exists {
				samePortSvrs[host] = vs
			} else {
				return goutil.NewErrorf(ErrCodeNewServerFail, ErrMsgNewServerFail, fmt.Sprintf("vserver host %s duplicated on listen port %d", host, k))
			}
		}
	}

	for k, lsn := range m.listeners {
		if lsn.tls {
			if svrs, ok := m.vServers[k]; ok {
				if len(svrs) > 1 {
					return goutil.NewErrorf(ErrCodeNewServerFail, ErrMsgNewServerFail, fmt.Sprintf("v-server with tls port %d duplicated", k))
				}
			}
		}
	}

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
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendDef, CfgBackendDefGroupList)
		}
		for _, v := range gl.([]interface{}) {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.String {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendDef, CfgBackendDefGroupList)
			}
			def.backendGroupList = append(def.backendGroupList, v.(string))
		}
	}

	// backend_list
	if bl, ok := cfg[CfgBackendDefBackendList]; ok {
		if rv := reflect.ValueOf(bl); rv.Kind() != reflect.Slice {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendList)
		}
		for _, v := range bl.([]interface{}) {
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.String {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendList)
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
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendMethend)
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
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendMethend)
		}
		def.Method = methodStr
	}

	// param_key
	if pk, ok := cfg[CfgBackendDefBackendParamkey]; ok {
		if rv := reflect.ValueOf(pk); rv.Kind() != reflect.String || pk.(string) == "" {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendParamkey)
		}
		def.ParamKey = pk.(string)
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
	if timeout, ok := cfg[CfgBackendDefWaitResponseTimeout]; ok {
		if i, ok := goutil.GetIntValue(timeout); ok {
			if i > 0 {
				def.WaitResponseTiemout = time.Duration(i) * time.Millisecond
			}
		}
	}

	if def.Alias != "" && (len(def.backendGroupList) > 0 || len(def.BackendList) > 0) && def.Method != "" {
		if def.Method == MethodUrlParam && def.ParamKey == "" {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendDef, CfgBackendDefBackendParamkey)
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
	weightInt := 1
	if len(list) > 1 {
		weightInt, err = strconv.Atoi(list[1])
		if err != nil {
			return nil, goutil.NewErrorf(ErrCodeNewBackendGroupFail, "invalid addr")
		}
		if weightInt < 1 || weightInt > 100 {
			return nil, goutil.NewErrorf(ErrCodeNewBackendGroupFail, "invalid addr")
		}
	}
	return &Backend{Ip: ip, Port: uint16(portInt), Weight: weightInt}, ErrorNoError
}

func (m *Paddy) newUpstream(obj map[string]interface{}) goutil.Error {
	if len(obj) == 0 {
		return goutil.NewErrorf(ErrCodeNewUpstream, ErrMsgNewUpstream, "map is empty")
	}

	ret := &Upstream{backendList: make([]string, 0)}
	for k, v := range obj {
		switch k {
		case CfgUpstreamAlias:
			ret.alias = goutil.GetStringValue(v)
			if _, ok := m.upstreams[ret.alias]; ok {
				return goutil.NewErrorf(ErrCodeUpstreamDup, ErrMsgUpstreamDup, ret.alias)
			}
		case CfgUpstreamConnTimeout:
			ret.connTimeout = time.Duration(goutil.GetIntValueDefault(v, 0)) * time.Millisecond
		case CfgUpstreamMethod:
			ret.method = goutil.GetStringValue(v)
			if !isTcpMethod(ret.method) {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgUpstream, CfgUpstreamMethod)
			}
		case CfgUpstreamBackendList:
			if rv := reflect.ValueOf(v); rv.Kind() != reflect.Slice {
				return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgUpstream, CfgUpstreamBackendList)
			}
			for _, backend := range v.([]interface{}) {
				s := goutil.GetStringValue(backend)
				if !validateTcp4Addr(s) {
					return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgUpstream, CfgUpstreamBackendList)
				}
				ret.backendList = append(ret.backendList, s)
			}
		}
	}
	if ret.alias == "" || ret.method == "" || len(ret.backendList) == 0 {
		return goutil.NewErrorf(ErrCodeNewUpstream, ErrMsgNewUpstream, "need more params definition")
	}
	m.upstreams[ret.alias] = ret

	return ErrorNoError
}

func (m *Paddy) newBackendGroup(groupName string, addrList []interface{}) goutil.Error {
	if groupName == "" {
		return goutil.NewErrorf(ErrCodeNewBackendGroupFail, "groupName is empty")
	}
	if len(addrList) == 0 {
		return goutil.NewErrorf(ErrCodeNewBackendGroupFail, "addrList is empty")
	}
	var backends []Backend
	for _, v := range addrList {
		if rv := reflect.ValueOf(v); rv.Kind() != reflect.String {
			return goutil.NewErrorf(ErrCodeCfgItem2Invalid, ErrMsgCfgItem2Invalid, CfgBackendGroup, groupName)
		}
		if backend, err := m.newBackend(v.(string)); err.Code != ErrCodeNoError {
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

func (m *Paddy) findHttpListenerFile(portInt uint16) *os.File {
	for port, lsn := range m.listeners {
		if portInt == port {
			if f, err := lsn.tcpListener.File(); err == nil {
				return f
			}
		}
	}
	return nil
}

func (m *Paddy) findTcpListenerFile(portInt uint16) *os.File {
	for _, ts := range m.tcpServers {
		for port, lsn := range ts.listeners {
			if portInt == port {
				if f, err := lsn.File(); err == nil {
					return f
				}
			}
		}
	}
	return nil
}

// envVarValue fd:port,fd:port,fd:port,...
func (m *Paddy) GenerateHttpInheritedPortsEnv(beginFd uintptr, originPaddy *Paddy) (noCloseFds []*os.File, envVarValue string) {
	var ret []int

	// http listener
	for k, lsnO := range originPaddy.listeners {
		// 如果新老配置的端口相同，tls相同，保留该句柄不关闭供子进程继承
		if lsn, ok := m.listeners[k]; ok && lsn.tls == lsnO.tls {
			ret = append(ret, int(k))
		}
	}

	sort.Ints(ret)
	curFd := beginFd
	for _, portInt := range ret {
		if f := originPaddy.findHttpListenerFile(uint16(portInt)); f != nil {
			noCloseFds = append(noCloseFds, f)
			if envVarValue != "" {
				envVarValue += ","
			}
			envVarValue += fmt.Sprintf("%d:%d", curFd, portInt)
			curFd++
		}
	}

	return noCloseFds, envVarValue
}

// envVarValue fd:port,fd:port,fd:port,...
func (m *Paddy) GenerateTcpInheritedPortsEnv(beginFd uintptr, originPaddy *Paddy) (noCloseFds []*os.File, envVarValue string) {
	var ret []int

	// tcp
	for _, ov := range originPaddy.tcpServers {
		for k := range ov.listeners {
			for _, nv := range m.tcpServers {
				if _, ok := nv.listeners[k]; ok {
					ret = append(ret, int(k))
				}
			}
		}
	}

	sort.Ints(ret)
	curFd := beginFd
	for _, portInt := range ret {
		if f := originPaddy.findTcpListenerFile(uint16(portInt)); f != nil {
			noCloseFds = append(noCloseFds, f)
			if envVarValue != "" {
				envVarValue += ","
			}
			envVarValue += fmt.Sprintf("%d:%d", curFd, portInt)
			curFd++
		}
	}

	return noCloseFds, envVarValue
}

// envVarValue fd:port,fd:port,fd:port,...
func (m *Paddy) GetInheritedPortsFromEnv(envVar string) (inheritedFds []uintptr, inheritedPorts []uint16) {

	varStr, found := os.LookupEnv(envVar)
	if !found {
		glog.Infof("%s not found", envVar)
		return nil, nil
	}
	glog.Infof("%s： %s", envVar, varStr)
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
	inheritedPortsEnvVar := EnvVarInheritedListenerHttp
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

	// tcp listen
	for _, v := range m.tcpServers {
		if err := v.startListen(); err != nil {
			return goutil.NewErrorf(ErrCodeCommonError, fmt.Sprintf("listn tcp server fail, %s", err.Error()))
		}
	}

	// http listen
	for port, lsnObj := range m.listeners {
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
		paddyListener := &Listener{port: port, tcpListener: lsn, tls: lsnObj.tls}
		paddyListener.httpServer = &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: m.handler}
		m.listeners[port] = paddyListener
		if lsnObj.tls {
			go func() {
				if svrs, ok := m.vServers[port]; !ok {
					panic(fmt.Errorf("v-server with port %d not exists", port))
				} else if len(svrs) > 1 {
					panic(fmt.Errorf("v-server with tls port %d duplicated", port))
				} else {
					for _, vs := range svrs {
						if err := paddyListener.httpServer.ServeTLS(lsn, vs.tlsCert, vs.tlsCertKey); err != nil {
							panic(err)
						}
						break
					}
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

	// kill parent process
	if len(inheritedFds) > 0 {
		if ppid := os.Getppid(); ppid > 1 {
			syscall.Kill(ppid, syscall.SIGTERM)
		}
	}

	// write pid file
	if m.pidFile != "" {
		pid := os.Getpid()
		if err := ioutil.WriteFile(m.pidFile, []byte(fmt.Sprintf("%d", pid)), 0666); err != nil {
			glog.Errorf("write pid file fail, %s", err.Error())
		} else {
			glog.Infof("write pid %d to %s\n", pid, m.pidFile)
		}
	}

	m.ready = true
	return goutil.NewError(ErrCodeNoError, "")
}
