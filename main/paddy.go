package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/truexf/goutil"
	"github.com/truxf/paddy"
)

var (
	configFile = flag.String("configFile", "", "config file")
	instance   *paddy.Paddy
)

func main() {
	flag.Parse()

	InitLog()

	evn := os.Environ()
	isRestart := false
	for _, v := range evn {
		if strings.HasPrefix(v, "restart=") {
			isRestart = true
		}
	}
	if !isRestart {
		//became a daemon process
		if err := daemonize(); err != nil {
			os.Stdout.WriteString(err.Error() + "\n")
			return
		}
	}

	signalDef()

	cfgFile := *configFile
	if cfgFile == "" {
		cfgFile = filepath.Join(goutil.GetExePath(), "default.config")
	}
	s, err := paddy.NewPaddy(cfgFile)
	if err.Code == paddy.ErrCodeNoError {
		instance = s
	} else {
		Log(err.Error())
		return
	}
	if err := instance.StartListen(); err.Code != paddy.ErrCodeNoError {
		Log(err.Error())
		return
	}

	c := make(chan int)
	<-c
}

func InitLog() {
	//todo
}

func Log(s string) {
	//todo
}
func FlushLog() {
	//todo
}

func daemonize() error {
	envs := os.Environ()
	for _, v := range envs {
		kv := strings.Split(v, "=")
		if len(kv) == 2 && kv[0] == "ppid" {
			return nil
		}
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, _ = filepath.EvalSymlinks(exePath)
	//daemonize
	pid := os.Getpid()
	envs = append(envs, fmt.Sprintf("ppid=%d", pid))
	workDir, _ := os.Getwd()
	_, err = os.StartProcess(exePath, os.Args, &os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Dir: workDir,
		Env: envs,
		// Sys: &syscall.SysProcAttr{Setsid: true, Noctty: true},
	})
	if err != nil {
		return err
	}
	envs = os.Environ()
	envPpid := -100
	for _, v := range envs {
		kv := strings.Split(v, "=")
		if len(kv) == 2 && kv[0] == "ppid" {
			envPpid, _ = strconv.Atoi(kv[1])
			break
		}
	}
	if envPpid == -100 {
		//parent process
		os.Exit(0)
	}
	return nil
}

func signalDef() {
	cSignal := make(chan os.Signal, 10)
	signal.Notify(cSignal, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for {
			sig := <-cSignal
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				Log(fmt.Sprintf("%s,received signal %d, terminate process\n", time.Now().Format("2006-01-02 15:04:05"), sig))
				FlushLog()
				signal.Stop(cSignal)
				os.Exit(-1)
			case syscall.SIGUSR1:
				Log(fmt.Sprintf("%s,received signal SIGUSR1, close process\n", time.Now().Format("2006-01-02 15:04:05")))
				FlushLog()
				signal.Stop(cSignal)
				os.Exit(0)
			case syscall.SIGUSR2:
				signal.Stop(cSignal)
				Log(fmt.Sprintf("%s,received signal SIGUSR2, restart process\n", time.Now().Format("2006-01-02 15:04:05")))
				if err := restartProcess(); err != nil {
					Log(fmt.Sprintf("%s,received signal SIGUSR2, restart process fail, %s\n", time.Now().Format("2006-01-02 15:04:05"), err.Error()))
				}
			case syscall.SIGHUP:
				Log(fmt.Sprintf("%s,received signal SIGHUP, ignore", time.Now().Format("2006-01-02 15:04:05")))
			}
		}
	}()
}

func restartProcess() (err error) {
	argv0, err := exec.LookPath(os.Args[0])
	if err != nil {
		return err
	}

	wd := goutil.GetExePath()
	var env []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "restart=") {
			env = append(env, v)
		}
	}
	env = append(env, "restart=1")

	allFiles := []*os.File{os.Stdin, os.Stdout, os.Stderr}

	newConfig, gErr := paddy.NewPaddy(instance.GetConfigFile())
	if gErr.Code != paddy.ErrCodeNoError {
		return fmt.Errorf(gErr.Error())
	}
	noCloseFds, envVarValue := newConfig.GenerateInheritedPortsEnv(uintptr(len(allFiles)), instance)

	allFiles = append(allFiles, noCloseFds...)
	env = append(env, fmt.Sprintf("%s=%s", paddy.EnvVarInheritedListener, envVarValue))

	_, err = os.StartProcess(argv0, os.Args, &os.ProcAttr{
		Dir:   wd,
		Env:   env,
		Files: allFiles,
	})
	return err
}
