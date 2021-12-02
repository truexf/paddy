// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/truexf/goutil/lblhttpclient"
)

func SplitByLine(s string) (ret []string) {
	if s == "" {
		return make([]string, 0)
	}
	ret3 := make([]string, 0)
	ret2 := make([]string, 0)
	var tmp []string
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

func validateTcp4Addr(addr string) bool {
	if addr == "" {
		return false
	}
	lst := strings.Split(addr, "#")
	if len(lst) > 2 {
		return false
	}
	if w, err := strconv.Atoi(lst[1]); err != nil || w < 1 || w > 100 {
		return false
	}
	lst = strings.Split(lst[0], ":")
	if len(lst) != 2 {
		return false
	}
	if port, err := strconv.Atoi(lst[1]); err != nil || port <= 0 || port >= math.MaxUint16 {
		return false
	}
	if _, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%s", lst[0], lst[1])); err != nil {
		return false
	}
	return true
}
