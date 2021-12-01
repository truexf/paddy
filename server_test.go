// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
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

var paddyInst *Paddy

func startListen() {
	svr, err := NewPaddy("default.config")
	if err.Code != ErrCodeNoError {
		panic(fmt.Sprintf("load config fail, %s", err.Error()))
	}
	if err := svr.StartListen(); err.Code != ErrCodeNoError {
		panic(err.Error())
	}
	paddyInst = svr
}

var one sync.Once

func TestResponseDirected(t *testing.T) {
	// return
	fmt.Println("TestResponseDirected\n=======================")
	one.Do(startListen)
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
	one.Do(startListen)
	fmt.Println("TestProxyPass\n=======================")
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
	one.Do(startListen)
	fmt.Println("TestBackend\n=======================")
	time.Sleep(time.Second * 2)
	if resp, err := http.Get("http://localhost:8081/backend"); err != nil {
		t.Fatal(err.Error())
	} else {
		bts, _ := io.ReadAll(resp.Body)
		fmt.Println(resp.Status)
		fmt.Println(string(bts))
	}
}

func TestFileRoot(t *testing.T) {
	one.Do(startListen)
	fmt.Println("TestFileRoot\n=======================")
	time.Sleep(time.Second * 2)
	if resp, err := http.Get("http://localhost:8081/paddy/default.config"); err != nil {
		t.Fatal(err.Error())
	} else {
		bts, _ := io.ReadAll(resp.Body)
		fmt.Println(resp.Status)
		fmt.Println(string(bts))
	}
}

func TestInheritedEnv(t *testing.T) {
	one.Do(startListen)
	fmt.Println("TestInheritedEnv\n==============")

	newConfig, gErr := NewPaddy(paddyInst.GetConfigFile())
	if gErr.Code != ErrCodeNoError {
		t.Fatalf(gErr.Message)
	}
	allFiles := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	noCloseFds, envVarValue := newConfig.GenerateInheritedPortsEnv(uintptr(len(allFiles)), paddyInst)
	fmt.Println(envVarValue)
	for _, v := range noCloseFds {
		fmt.Printf("%d\n", v.Fd())
	}
}
