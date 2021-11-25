package paddy

import "strings"

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
