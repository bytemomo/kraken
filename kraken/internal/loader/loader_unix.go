//go:build unix

package loader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"
	cnd "bytemomo/trident/conduit"
)

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include "../../pkg/moduleabi/kraken_module_abi.h"
#include "../../pkg/moduleabi/kraken_module_abi_v2.h"

static void* my_dlopen(const char* p)              { return dlopen(p, RTLD_NOW); }
static void* my_dlsym(void* h, const char* s)      { return dlsym(h, s); }
static int   my_dlclose(void* h)                   { return dlclose(h); }
static const char* my_dlerror()                    { return dlerror(); }

// Thin bridge wrappers so Go can call function pointers.
static inline int call_kraken_run(KrakenRunFn f, const char* host, uint32_t port, uint32_t timeout_ms,
                                const char* params_json, KrakenRunResult** out_result) {
    return f(host, port, timeout_ms, params_json, out_result);
}

static inline void call_kraken_free(KrakenFreeFn f, void* p) { f(p); }

// V2 API wrappers
static inline int call_kraken_run_v2(KrakenRunV2Fn f, KrakenConnectionHandle conn, const KrakenConnectionOps* ops,
                                   const KrakenTarget* target, uint32_t timeout_ms,
                                   const char* params_json, KrakenRunResultV2** out_result) {
    return f(conn, ops, target, timeout_ms, params_json, out_result);
}

static inline void call_kraken_free_v2(KrakenFreeV2Fn f, void* p) { f(p); }

// V2 I/O operation callbacks (implemented in Go)
int64_t go_conduit_send(KrakenConnectionHandle conn, uint8_t* data, size_t len, uint32_t timeout_ms);
int64_t go_conduit_recv(KrakenConnectionHandle conn, uint8_t* buffer, size_t buffer_size, uint32_t timeout_ms);
KrakenConnectionInfo* go_conduit_get_info(KrakenConnectionHandle conn);
KrakenConnectionHandle go_conduit_open(KrakenConnectionHandle conn, uint32_t timeout_ms);
void go_conduit_close(KrakenConnectionHandle conn);

*/
import "C"

type nativeModule struct {
	handle unsafe.Pointer
}

func (m *nativeModule) Run(ctx context.Context, params map[string]any, t domain.Target, timeout time.Duration, conduit interface{}) (domain.RunResult, error) {
	abiConfig := ctx.Value(contextkeys.ABIConfig).(*domain.ABIConfig)

	symbol := abiConfig.Symbol
	if symbol == "" {
		symbol = "kraken_run"
	}

	if strings.HasSuffix(symbol, "_v2") || symbol == "kraken_run_v2" {
		return m.runV2(ctx, symbol, params, t, timeout, conduit)
	}

	// V1 API only supports network targets
	hp, ok := t.(domain.HostPort)
	if !ok {
		return domain.RunResult{}, fmt.Errorf("V1 ABI modules only support network targets, got %T", t)
	}

	return m.runV1(symbol, params, hp, timeout)
}

func (m *nativeModule) Close() error {
	if m.handle != nil {
		ret := C.my_dlclose(m.handle)
		if ret != 0 {
			return fmt.Errorf("dlclose failed: %s", C.GoString(C.my_dlerror()))
		}
	}
	return nil
}

func (m *nativeModule) runV1(symbol string, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	runPtr := C.my_dlsym(m.handle, csym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(%s) failed: %s", symbol, C.GoString(C.my_dlerror()))
	}
	run := (C.KrakenRunFn)(runPtr)

	freeSym := C.CString("kraken_free")
	defer C.free(unsafe.Pointer(freeSym))

	freePtr := C.my_dlsym(m.handle, freeSym)
	if freePtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(kraken_free) failed: %s", C.GoString(C.my_dlerror()))
	}
	freeFn := (C.KrakenFreeFn)(freePtr)

	hostC := C.CString(t.Host)
	defer C.free(unsafe.Pointer(hostC))

	portC := C.uint32_t(t.Port)
	timeoutMs := C.uint32_t(timeout.Milliseconds())

	paramsBytes, _ := json.Marshal(params)
	cParams := C.CString(string(paramsBytes))
	defer C.free(unsafe.Pointer(cParams))

	var outResult *C.KrakenRunResult

	ret := C.call_kraken_run(run, hostC, portC, timeoutMs, cParams, &outResult)
	if int(ret) != 0 {
		return domain.RunResult{}, fmt.Errorf("module returned error code %d", int(ret))
	}

	if outResult == nil {
		return domain.RunResult{}, errors.New("module returned empty result")
	}
	defer C.call_kraken_free(freeFn, unsafe.Pointer(outResult))

	return decodeRunResult(outResult)
}

func (m *nativeModule) runV2(ctx context.Context, symbol string, params map[string]any, t domain.Target, timeout time.Duration, conduit interface{}) (domain.RunResult, error) {
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	runPtr := C.my_dlsym(m.handle, csym)
	if runPtr == nil {
		return domain.RunResult{}, fmt.Errorf("dlsym(%s) failed: %s", symbol, C.GoString(C.my_dlerror()))
	}
	run := (C.KrakenRunV2Fn)(runPtr)

	freeSym := C.CString("kraken_free_v2")
	defer C.free(unsafe.Pointer(freeSym))

	freePtr := C.my_dlsym(m.handle, freeSym)
	if freePtr == nil {
		freeSym = C.CString("kraken_free")
		defer C.free(unsafe.Pointer(freeSym))
		freePtr = C.my_dlsym(m.handle, freeSym)
		if freePtr == nil {
			return domain.RunResult{}, fmt.Errorf("dlsym(kraken_free_v2/kraken_free) failed: %s", C.GoString(C.my_dlerror()))
		}
	}
	freeFn := (C.KrakenFreeV2Fn)(freePtr)

	var factory v2ConduitFactory
	if v := ctx.Value(contextkeys.ConduitFactory); v != nil {
		if f, ok := v.(v2ConduitFactory); ok {
			factory = f
		}
	}

	// Dial initial conduit if not provided but a factory exists.
	if conduit == nil && factory != nil {
		c, _, layers, err := factory(timeout)
		if err != nil {
			return domain.RunResult{}, fmt.Errorf("failed to dial conduit: %w", err)
		}
		conduit = c
		if len(layers) > 0 {
			ctx = context.WithValue(ctx, contextkeys.StackLayers, layers)
		}
	}

	var stackLayers []string
	if v := ctx.Value(contextkeys.StackLayers); v != nil {
		if sl, ok := v.([]string); ok {
			stackLayers = sl
		}
	}

	if len(stackLayers) == 0 {
		switch conduit.(type) {
		case cnd.Datagram:
			stackLayers = []string{"udp"}
		default:
			stackLayers = []string{"tcp"}
		}
	}

	// Get string representation before unsafe operations to avoid memory corruption
	remoteAddr := t.String()

	// Build C target struct based on target type
	var target C.KrakenTarget
	var hostC *C.char
	var ifaceC *C.char

	switch tt := t.(type) {
	case domain.HostPort:
		hostC = C.CString(tt.Host)
		defer C.free(unsafe.Pointer(hostC))

		target.kind = C.KRAKEN_TARGET_KIND_NETWORK
		network := (*C.KrakenHostPort)(unsafe.Pointer(&target.u[0]))
		network.host = hostC
		network.port = C.uint16_t(tt.Port)

	case domain.EtherCATMaster:
		ifaceC = C.CString(tt.Interface)
		defer C.free(unsafe.Pointer(ifaceC))
		macC := C.CString(tt.MACAddress.String())
		defer C.free(unsafe.Pointer(macC))

		target.kind = C.KRAKEN_TARGET_KIND_ETHERCAT
		ethercat := (*C.KrakenEtherCATTarget)(unsafe.Pointer(&target.u[0]))
		ethercat.iface = ifaceC
		ethercat.mac_address = macC
		ethercat.slave_count = C.uint32_t(tt.SlaveCount)
		if len(tt.Slaves) > 0 {
			ethercat.slaves = (*C.uint16_t)(C.malloc(C.size_t(len(tt.Slaves)) * C.size_t(unsafe.Sizeof(C.uint16_t(0)))))
			defer C.free(unsafe.Pointer(ethercat.slaves))
			cSlaves := unsafe.Slice(ethercat.slaves, len(tt.Slaves))
			for i, s := range tt.Slaves {
				cSlaves[i] = C.uint16_t(s)
			}
			ethercat.slaves_len = C.size_t(len(tt.Slaves))
		}

	default:
		return domain.RunResult{}, fmt.Errorf("unsupported target type: %T", t)
	}

	v2HandleMutex.Lock()
	handleID := v2HandleCounter
	v2HandleCounter++
	connHandle := C.KrakenConnectionHandle(unsafe.Pointer(handleID))

	info := buildConnectionInfo(conduit, stackLayers, remoteAddr)

	v2HandleMap[handleID] = &v2ConnectionHandle{conduit: conduit, info: info, factory: factory, stackLayers: stackLayers}
	v2HandleMutex.Unlock()

	var ops C.KrakenConnectionOps
	ops.send = C.KrakenSendFn(C.go_conduit_send)
	ops.recv = C.KrakenRecvFn(C.go_conduit_recv)
	ops.get_info = C.KrakenGetConnectionInfoFn(C.go_conduit_get_info)
	ops.open = C.KrakenOpenFn(C.go_conduit_open)
	ops.close = C.KrakenCloseFn(C.go_conduit_close)

	timeoutMs := C.uint32_t(timeout.Milliseconds())

	paramsBytes, _ := json.Marshal(params)
	cParams := C.CString(string(paramsBytes))
	defer C.free(unsafe.Pointer(cParams))

	var outResult *C.KrakenRunResultV2

	ret := C.call_kraken_run_v2(run, connHandle, &ops, &target, timeoutMs, cParams, &outResult)
	if int(ret) != 0 {
		cleanupHandle(handleID, true)
		return domain.RunResult{}, fmt.Errorf("module returned error code %d", int(ret))
	}

	if outResult == nil {
		cleanupHandle(handleID, true)
		return domain.RunResult{}, errors.New("module returned empty result")
	}
	defer C.call_kraken_free_v2(freeFn, unsafe.Pointer(outResult))
	cleanupHandle(handleID, true)

	return decodeRunResultV2(outResult)
}

func Load(path string) (LoadableModule, error) {
	var extension string
	switch runtime.GOOS {
	case "darwin":
		extension = ".dylib"
	case "linux":
		extension = ".so"
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	libPath := path + extension
	clib := C.CString(libPath)
	defer C.free(unsafe.Pointer(clib))

	handle := C.my_dlopen(clib)
	if handle == nil {
		return nil, fmt.Errorf("dlopen(%s) failed: %s", libPath, C.GoString(C.my_dlerror()))
	}

	return &nativeModule{handle: handle}, nil
}
