// Copyright 2021 fangyousong(方友松). All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package paddy

import (
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var AllTcpMethods = []string{TcpMethodLeastConn, TcpMethodRoundrobin, TcpMethodRadom, TcpMethodIpHash}

const (
	TcpMethodLeastConn  = "leastconn"
	TcpMethodRoundrobin = "roundrobin"
	TcpMethodRadom      = "random"
	TcpMethodIpHash     = "iphash"

	MinTcpConnTimeout = time.Millisecond * 10
)

func isTcpMethod(method string) bool {
	for _, v := range AllTcpMethods {
		if v == method {
			return true
		}
	}
	return false
}

type TcpBackend struct {
	connNum  int64
	addr     *net.TCPAddr
	conns    map[string]*net.TCPConn //key: client-addr(ip:port)
	connLock sync.RWMutex
}

func newTcpBackend(ip string, port uint16) (*TcpBackend, error) {
	ret := &TcpBackend{conns: make(map[string]*net.TCPConn)}
	if addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", ip, port)); err != nil {
		return nil, err
	} else {
		ret.addr = addr
		return ret, nil
	}
}

func (m *TcpBackend) newConn(clientAddr string, timeout time.Duration) (*net.TCPConn, error) {
	ret, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", m.addr.IP.String(), m.addr.Port), timeout)
	if err != nil {
		return nil, err
	}
	m.connLock.Lock()
	defer m.connLock.Unlock()
	m.conns[clientAddr] = ret.(*net.TCPConn)
	atomic.AddInt64(&m.connNum, 1)
	return ret.(*net.TCPConn), nil
}

type TcpLbClient struct {
	method          string
	backendList     []*TcpBackend
	roundrobinIndex int
	randObj         *rand.Rand
	connTimeout     time.Duration
}

func newTcpLbClient(backends []string, method string, connTimeout time.Duration) (*TcpLbClient, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends")
	}
	switch method {
	case TcpMethodLeastConn, TcpMethodRoundrobin, TcpMethodRadom, TcpMethodIpHash:
	default:
		return nil, fmt.Errorf("method %s is invalid", method)
	}
	if connTimeout < MinTcpConnTimeout {
		connTimeout = MinTcpConnTimeout
	}
	ret := &TcpLbClient{method: method, backendList: make([]*TcpBackend, 0), randObj: rand.New(rand.NewSource(time.Now().UnixNano())),
		connTimeout: connTimeout,
	}
	for _, backend := range backends {
		weight := 1
		lst := strings.Split(backend, "#")
		if len(lst) != 2 {
			return nil, fmt.Errorf("invalid backend: %s", backend)
		}
		if i, err := strconv.Atoi(lst[1]); err != nil || i > 100 {
			return nil, fmt.Errorf("invalid backend: %s, weight too large", backend)
		} else {
			weight = i
		}
		lst = strings.Split(lst[0], ":")
		if len(lst) != 2 {
			return nil, fmt.Errorf("invalid backend: %s", backend)
		}
		port, err := strconv.Atoi(lst[1])
		if err != nil || port <= 0 || port >= math.MaxUint16 {
			return nil, fmt.Errorf("invalid backend: %s, port is invalid", backend)
		}
		ip := lst[0]
		if ip == "" {
			return nil, fmt.Errorf("invalid backend: %s, ip is invalid", backend)
		}
		for i := 0; i < weight; i++ {
			if backendObj, err := newTcpBackend(ip, uint16(port)); err != nil {
				return nil, fmt.Errorf("new backend fail, ip %s, port %d, %s", ip, port, err.Error())
			} else {
				ret.backendList = append(ret.backendList, backendObj)
			}
		}
	}
	if len(ret.backendList) == 0 {
		return nil, fmt.Errorf("no backend created")
	}
	return ret, nil
}

// clientAddr ip:port
func (m *TcpLbClient) ConnectBackend(clientAddr string) (*net.TCPConn, error) {
	if len(m.backendList) == 0 {
		return nil, fmt.Errorf("no backend")
	}
	switch m.method {
	case TcpMethodLeastConn:
		var minConn int64 = math.MaxInt64
		var backend *TcpBackend = nil
		for _, v := range m.backendList {
			num := atomic.LoadInt64(&v.connNum)
			if num <= 0 {
				return v.newConn(clientAddr, m.connTimeout)
			}
			if v.connNum < int64(minConn) {
				backend = v
				minConn = num
			}
		}
		if backend == nil {
			return nil, fmt.Errorf("no backend selected by leastconn")
		}
		return backend.newConn(clientAddr, m.connTimeout)
	case TcpMethodRoundrobin:
		m.roundrobinIndex++
		if m.roundrobinIndex >= len(m.backendList) {
			m.roundrobinIndex = 0
		}
		return m.backendList[m.roundrobinIndex].newConn(clientAddr, m.connTimeout)
	case TcpMethodRadom:
		idx := m.randObj.Intn(len(m.backendList))
		return m.backendList[idx].newConn(clientAddr, m.connTimeout)
	case TcpMethodIpHash:
		lst := strings.Split(clientAddr, ":")
		if len(lst) != 2 {
			return nil, fmt.Errorf("invalid clientAddr: %s", clientAddr)
		}
		fnv32 := fnv.New32()
		io.WriteString(fnv32, lst[0])
		idx := fnv32.Sum32()
		idx = idx % uint32(len(m.backendList))
		return m.backendList[idx].newConn(clientAddr, m.connTimeout)
	default:
		return nil, fmt.Errorf("method %s is invalid", m.method)
	}
}

func (m *TcpLbClient) removeConn(clientAddr string) {
	for _, backend := range m.backendList {
		backend.connLock.RLock()
		conn, ok := backend.conns[clientAddr]
		backend.connLock.RUnlock()
		if ok {
			backend.connLock.Lock()
			delete(backend.conns, clientAddr)
			atomic.AddInt64(&backend.connNum, -1)
			backend.connLock.Unlock()
			conn.Close()
			return
		}
	}
}
