package paddy

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestConfigLoad(t *testing.T) {
	svr, err := NewPaddy("default.config")
	if err.Code != ErrCodeNoError {
		t.Fatalf("load config fail, %s", err.Error())
	}
	fmt.Println("print backend groups")
	for k, v := range svr.backendGroups {
		fmt.Printf("%s: %v\n", k, v)
	}

	fmt.Println("\nprint backend defs")
	for k, v := range svr.backendDefs {
		fmt.Printf("%s: %v\n", k, v)
	}

	fmt.Printf("\nprint v-servers")
	for _, v := range svr.vServers {
		fmt.Printf("%v\n", v)
	}
}

func startListen() {
	svr, err := NewPaddy("default.config")
	if err.Code != ErrCodeNoError {
		panic(fmt.Sprintf("load config fail, %s", err.Error()))
	}
	if err := svr.StartListen(); err.Code != ErrCodeNoError {
		panic(err.Error())
	}
}

func TestResponseDirected(t *testing.T) {
	return

	startListen()
	time.Sleep(time.Second * 2)
	if resp, err := http.Get("http://localhost:8081/response_direct?echo=hello"); err != nil {
		t.Fatal(err.Error())
	} else {
		bts, _ := io.ReadAll(resp.Body)
		fmt.Println(resp.Status)
		fmt.Println(string(bts))
	}
}

func TestProxyPass(t *testing.T) {
	return
	startListen()

	time.Sleep(time.Second * 2)
	if resp, err := http.Get("http://localhost:8081/proxy_pass"); err != nil {
		t.Fatal(err.Error())
	} else {
		bts, _ := io.ReadAll(resp.Body)
		fmt.Println(resp.Status)
		fmt.Println(string(bts))
	}
}

func TestBackend(t *testing.T) {
	// return
	startListen()

	time.Sleep(time.Second * 2)
	if resp, err := http.Get("http://localhost:8081/backend"); err != nil {
		t.Fatal(err.Error())
	} else {
		bts, _ := io.ReadAll(resp.Body)
		fmt.Println(resp.Status)
		fmt.Println(string(bts))
	}
}
