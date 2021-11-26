package paddy

import (
	"net/http"
	"strings"

	"github.com/truexf/goutil/lblhttpclient"
)

func SplitByLine(s string) (ret []string) {
	if s == "" {
		return make([]string, 0)
	}
	ret3 := make([]string, 0)
	ret2 := make([]string, 0)
	tmp := make([]string, 0)
	ret1 := strings.Split(s, "\r\n")
	var j int
	j = len(ret1)
	for i := 0; i < j; i++ {
		tmp = strings.Split(ret1[i], "\r")
		x := len(tmp)
		for k := 0; k < x; k++ {
			ret2 = append(ret2, tmp[k])
		}
	}
	j = len(ret2)
	for i := 0; i < j; i++ {
		tmp = strings.Split(ret2[i], "\n")
		x := len(tmp)
		for k := 0; k < x; k++ {
			ret3 = append(ret3, tmp[k])
		}
	}
	return ret3
}

func TrimJsonComment(jsn string) string {
	btsList := SplitByLine(jsn)
	sRet := ""
	for _, v := range btsList {
		v1 := strings.TrimSpace(v)
		if len(v1) >= 2 && v1[:2] == "//" {
			continue
		}
		if sRet == "" {
			sRet += "\n"
		}
		sRet += v
	}
	return sRet
}

func MethodStrToI(ms string) lblhttpclient.LoadBalanceMethod {
	iMethod := lblhttpclient.MethodMinPending
	switch ms {
	case MethodIpHash:
		iMethod = lblhttpclient.MethodIpHash
	case MethodJsonExp:
		iMethod = lblhttpclient.MethodJsonExp
	case MethodRandom:
		iMethod = lblhttpclient.MethodRandom
	case MethodRoundrobin:
		iMethod = lblhttpclient.MethodRoundrobin
	case MethodUrlParam:
		iMethod = lblhttpclient.MethodUrlParam
	case MethodMinPending:
		iMethod = lblhttpclient.MethodMinPending
	}
	return iMethod
}

func RemoteIp(r *http.Request) string {
	//X-Real-Ip
	//X-Forwarded-For
	for k, v := range r.Header {
		if strings.EqualFold(k, "X-Real-Ip") && len(v) > 0 && len(v[0]) > 0 {
			return v[0]
		}
	}

	for k, v := range r.Header {
		if strings.EqualFold(k, "X-Forwarded-For") && len(v) > 0 && len(v[0]) > 0 {
			return v[0]
		}
	}

	lst := strings.Split(r.RemoteAddr, ":")
	if len(lst) > 0 {
		return lst[0]
	}
	return ""

}
