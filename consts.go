// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import "github.com/truexf/goutil"

var (
	ErrorNoError = goutil.NewError(ErrCodeNoError, "")

	DefaultBackendMaxIdleConn         = 10
	DefaultBackendWaitResponseTimeout = 2000
	DefaultBackendConnTimeout         = 3000

	AllMethods = []string{MethodRandom, MethodRoundrobin, MethodMinPending, MethodIpHash, MethodUrlParam}
)

const (
	// for restart
	EnvVarInheritedListener = "inherited_listener"

	ContextVarResponseFilter = "__response_filter__"

	// can use in location_regexp.proxy_pass
	MacroBackend = "{{backend}}"
	MacroDomain  = "{{domain}}"
	MacroHost    = "{{host}}"
	MacroPort    = "{{port}}"
	MacroURI     = "{{uri}}"
	MacroPath    = "{{path}}"
	MacroParams  = "{{params}}"
)

const (
	ErrCodeNoError             = 0
	ErrCodeConfigNotExist      = 100
	ErrMsgConfigNotExist       = "config file %s not exist"
	ErrCodeConfigReadFail      = 101
	ErrMsgConfigReadFail       = "config file %s read fail, %s"
	ErrCodeCfgItemInvalid      = 102
	ErrMsgCfgItemInvalid       = "config item: %s is invalid"
	ErrCodeCfgItem2Invalid     = 103
	ErrMsgCfgItem2Invalid      = "config item: %s.%s is invalid"
	ErrCodeNewBackendGroupFail = 104
	ErrMsgNewBackendGroupFail  = "new backend group fail, %s"
	ErrCodeNewBackendDefFail   = 105
	ErrMsgNewBackendDefFail    = "new backend def fail, %s"
	ErrCodeBackendGroupDup     = 106
	ErrMsgBackendGroupDup      = "backend group: %s duplicated"
	ErrCodeBackendDefDup       = 107
	ErrMsgBackendDefDup        = "backend def: %s duplicated"
	ErrCodeNewServerFail       = 108
	ErrMsgNewServerFail        = "new server fail, %s"
	ErrCodeListenPortDup       = 109
	ErrMsgListenPortDup        = "listen port: %d duplicated"
	ErrCodeHostDup             = 110
	ErrMsgHostDup              = "host: %s duplicated"
	ErrCodeCfgItem3Invalid     = 111
	ErrMsgCfgItem3Invalid      = "config item: %s.%s.%s is invalid"
	ErrCodeListenFail          = 112
	ErrCodePluginDup           = 113
	ErrMsgPluginDup            = "plugin %s duplicated"
	ErrCodeDemo                = 114
	ErrMsgDemo                 = "demo error %s"
	ErrCodeJsonexpExecute      = 115
	ErrMsgJsonexpExecute       = "execute jsonexp fail, %s"
	ErrCodeBackendNotFound     = 116
	ErrMsgBackendNotFound      = "backend %s not found"
	ErrCodeBackendRequestFail  = 117
	ErrMsgBackendRequestFail   = "backend %s request fail, %s"
	ErrCodeCommonError         = 118
)

const (
	MethodRoundrobin = "roundrobin"
	MethodMinPending = "minpending"
	MethodRandom     = "random"
	MethodIpHash     = "iphash"
	MethodUrlParam   = "uri_param"
)

const (
	CfgPidFile                       = "pid_file"
	CfgLogDir                        = "log_dir"
	CfgLogLevel                      = "log_level"
	CfgInclude                       = "include"
	CfgBackendGroup                  = "backend_group"
	CfgBackendDef                    = "backend_def"
	CfgBackendDefAlias               = "alias"
	CfgBackendDefGroupList           = "group_list"
	CfgBackendDefBackendList         = "backend_list"
	CfgBackendDefBackendMethend      = "method"
	CfgBackendDefBackendParamkey     = "param_key"
	CfgBackendDefJsonexp             = "jsonexp"
	CfgBackendDefMaxIdleConn         = "max_idle_conn"
	CfgBackendDefWaitResponseTimeout = "wait_response_timeout"

	CfgServer                              = "server"
	CfgServerListen                        = "listen"
	CfgServerHosts                         = "hosts"
	CfgServerTlsCert                       = "tls_cert"
	CfgServerTlsCertKey                    = "tls_cert_key"
	CfgServerSessionTimeout                = "tls_cert_session_timeout"
	CfgServerLocationRegexp                = "location_regexp"
	CfgServerLocationRegexpExp             = "exp"
	CfgServerLocationRegexpFileRoot        = "file_root"
	CfgServerLocationRegexpBackend         = "backend"
	CfgServerLocationRegexpProxyPass       = "proxy_pass"
	CfgServerLocationRegexpRequestFilter   = "request_filter"
	CfgServerLocationRegexpResponseFilter  = "response_filter"
	CfgServerLocationJsonexp               = "location_jsonexp"
	CfgServerLocationJsonexpExp            = "exp"
	CfgServerLocationJsonexpRequestFilter  = "request_filter"
	CfgServerLocationJsonexpResponseFilter = "response_filter"
)

var MimeTypeMap map[string]string = map[string]string{
	"3gp":     "video/3gpp",
	"3gpp":    "video/3gpp",
	"7z":      "application/x-7z-compressed",
	"ai":      "application/postscript",
	"asf":     "video/x-ms-asf",
	"asx":     "video/x-ms-asf",
	"atom":    "application/atom+xml",
	"avi":     "video/x-msvideo",
	"bin":     "application/octet-stream",
	"bmp":     "image/x-ms-bmp",
	"cco":     "application/x-cocoa",
	"crt":     "application/x-x509-ca-cert",
	"css":     "text/css",
	"deb":     "application/octet-stream",
	"der":     "application/x-x509-ca-cert",
	"dll":     "application/octet-stream",
	"dmg":     "application/octet-stream",
	"doc":     "application/msword",
	"docx":    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"ear":     "application/java-archive",
	"eot":     "application/vnd.ms-fontobject",
	"eps":     "application/postscript",
	"exe":     "application/octet-stream",
	"flv":     "video/x-flv",
	"gif":     "image/gif",
	"hqx":     "application/mac-binhex40",
	"htc":     "text/x-component",
	"htm":     "text/html",
	"html":    "text/html",
	"ico":     "image/x-icon",
	"img":     "application/octet-stream",
	"iso":     "application/octet-stream",
	"jad":     "text/vnd.sun.j2me.app-descriptor",
	"jar":     "application/java-archive",
	"jardiff": "application/x-java-archive-diff",
	"jng":     "image/x-jng",
	"jnlp":    "application/x-java-jnlp-file",
	"jpeg":    "image/jpeg",
	"jpg":     "image/jpeg",
	"js":      "application/javascript",
	"json":    "application/json",
	"kar":     "audio/midi",
	"kml":     "application/vnd.google-earth.kml+xml",
	"kmz":     "application/vnd.google-earth.kmz",
	"m3u8":    "application/vnd.apple.mpegurl",
	"m4a":     "audio/x-m4a",
	"m4v":     "video/x-m4v",
	"mid":     "audio/midi",
	"midi":    "audio/midi",
	"mml":     "text/mathml",
	"mng":     "video/x-mng",
	"mov":     "video/quicktime",
	"mp3":     "audio/mpeg",
	"mp4":     "video/mp4",
	"mpeg":    "video/mpeg",
	"mpg":     "video/mpeg",
	"msi":     "application/octet-stream",
	"msm":     "application/octet-stream",
	"msp":     "application/octet-stream",
	"ogg":     "audio/ogg",
	"pdb":     "application/x-pilot",
	"pdf":     "application/pdf",
	"pem":     "application/x-x509-ca-cert",
	"pl":      "application/x-perl",
	"pm":      "application/x-perl",
	"png":     "image/png",
	"ppt":     "application/vnd.ms-powerpoint",
	"pptx":    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"prc":     "application/x-pilot",
	"ps":      "application/postscript",
	"ra":      "audio/x-realaudio",
	"rar":     "application/x-rar-compressed",
	"rpm":     "application/x-redhat-package-manager",
	"rss":     "application/rss+xml",
	"rtf":     "application/rtf",
	"run":     "application/x-makeself",
	"sea":     "application/x-sea",
	"shtml":   "text/html",
	"sit":     "application/x-stuffit",
	"svg":     "image/svg+xml",
	"svgz":    "image/svg+xml",
	"swf":     "application/x-shockwave-flash",
	"tcl":     "application/x-tcl",
	"tif":     "image/tiff",
	"tiff":    "image/tiff",
	"tk":      "application/x-tcl",
	"ts":      "video/mp2t",
	"txt":     "text/plain",
	"war":     "application/java-archive",
	"wbmp":    "image/vnd.wap.wbmp",
	"webm":    "video/webm",
	"webp":    "image/webp",
	"wml":     "text/vnd.wap.wml",
	"wmlc":    "application/vnd.wap.wmlc",
	"wmv":     "video/x-ms-wmv",
	"woff":    "application/font-woff",
	"xhtml":   "application/xhtml+xml",
	"xls":     "application/vnd.ms-excel",
	"xlsx":    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"xml":     "text/xml",
	"xpi":     "application/x-xpinstall",
	"xspf":    "application/xspf+xml",
	"zip":     "application/zip",
}
