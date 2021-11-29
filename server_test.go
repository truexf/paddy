package paddy

import (
	"fmt"
	"testing"
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
