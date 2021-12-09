package plugin

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/truxf/paddy"
)

var paddyInst *paddy.Paddy
var one sync.Once

func startListen() {
	svr, err := paddy.NewPaddy("../default.config")
	if err.Code != paddy.ErrCodeNoError {
		panic(fmt.Sprintf("load config fail, %s", err.Error()))
	}
	if err := svr.StartListen(); err.Code != paddy.ErrCodeNoError {
		panic(err.Error())
	}
	paddyInst = svr
}

func TestUpstream(t *testing.T) {
	one.Do(startListen)
	paddyInst.RegisterPlugin(&DemoPlugin{})
	time.Sleep(time.Second * 2)
	if resp, err := http.Get("http://localhost:8081/ping"); err != nil {
		t.Fatal(err.Error())
	} else {
		bts, _ := io.ReadAll(resp.Body)
		fmt.Println(resp.Status)
		fmt.Println(string(bts))
	}
}
