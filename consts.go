package paddy

import "github.com/truexf/goutil"

var (
	ErrorNoError = goutil.NewError(ErrCodeNoError, "")
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
)

var AllMethods = []string{MethodRandom, MethodRoundrobin, MethodMinPending, MethodJsonExp, MethodIpHash, MethodUrlParam}

const (
	MethodRoundrobin = "roundrobin"
	MethodMinPending = "minpending"
	MethodRandom     = "random"
	MethodIpHash     = "iphash"
	MethodJsonExp    = "jsonexp"
	MethodUrlParam   = "urlparam"
)

const (
	CfgInclude                   = "include"
	CfgBackendGroup              = "backend_group"
	CfgBackendDef                = "backend_def"
	CfgBackendDefAlias           = "alias"
	CfgBackendDefGroupList       = "group_list"
	CfgBackendDefBackendList     = "backend_list"
	CfgBackendDefBackendMethend  = "method"
	CfgBackendDefBackendParamkey = "param_key"
	CfgBackendDefJsonexp         = "jsonexp"

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
	CfgServerLocationRegexpRequestFilter   = "request_filter"
	CfgServerLocationRegexpResponseFilter  = "response_filter"
	CfgServerLocationJsonexp               = "location_jsonexp"
	CfgServerLocationJsonexpExp            = "exp"
	CfgServerLocationJsonexpRequestFilter  = "request_filter"
	CfgServerLocationJsonexpResponseFilter = "response_filter"
)

const (
	EnvVarInheritedListener = "inherited_listener"
)
