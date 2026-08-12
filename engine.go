// ggmcp engine.go - 内核内存引擎: MemoryDriver supercall握手 + ioctl读写 + 搜索
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ---------- syscall 常量 ----------
const (
	SYS_IOCTL             = 29
	SYS_PROCESS_VM_READV  = 270
	SYS_PROCESS_VM_WRITEV = 271
	SUPERCALL_NR          = 45
	SUPERCALL_KPM_CONTROL = 0x1022
	SUPERCALL_VER         = 0x1008
)

// iovec arm64: {void* base; size_t len}
type iovec struct {
	Base unsafe.Pointer
	Len  uint64
}

// kpm_read 与内核驱动一致
type kpmRead struct {
	Key    uint64
	Pid    int32
	Size   int32
	Addr   uint64
	Buffer unsafe.Pointer
}

// KernelMem 内核读写引擎 (MemoryDriver: socket + ioctl 0x7e1a/0x7e1b)
type KernelMem struct {
	mu     sync.Mutex
	fd     int
	ok     bool
	reason string
}

// kreadMD 与 MemoryDriver 协议一致的struct: {pid,pad,addr,buffer,size}
type kreadMD struct {
	Pid    uint32
	Pad    uint32
	Addr   uint64
	Buffer uint64
	Size   uint64
}

// Init 创建UDP socket作为驱动通道
func (k *KernelMem) Init() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		k.reason = fmt.Sprintf("socket failed: %v", err)
		return err
	}
	k.fd = fd
	k.ok = true
	k.reason = ""
	return nil
}

// kernelRead 单次 ioctl(fd, 0x7e1a, &kreadMD)
func (k *KernelMem) kernelRead(pid int, addr uintptr, buf []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.ok {
		return errors.New("kernel driver not initialized")
	}
	kr := kreadMD{
		Pid:    uint32(pid),
		Addr:   uint64(addr),
		Buffer: uint64(uintptr(unsafe.Pointer(&buf[0]))),
		Size:   uint64(len(buf)),
	}
	r, _, errno := syscall.Syscall(SYS_IOCTL, uintptr(k.fd), 0x7e1a, uintptr(unsafe.Pointer(&kr)))
	if errno != 0 {
		return errno
	}
	if int64(r) != int64(len(buf)) {
		return fmt.Errorf("kernel read short: got %d want %d", r, len(buf))
	}
	return nil
}

// kernelWrite 单次 ioctl(fd, 0x7e1b, &kreadMD)
func (k *KernelMem) kernelWrite(pid int, addr uintptr, buf []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.ok {
		return errors.New("kernel driver not initialized")
	}
	kr := kreadMD{
		Pid:    uint32(pid),
		Addr:   uint64(addr),
		Buffer: uint64(uintptr(unsafe.Pointer(&buf[0]))),
		Size:   uint64(len(buf)),
	}
	r, _, errno := syscall.Syscall(SYS_IOCTL, uintptr(k.fd), 0x7e1b, uintptr(unsafe.Pointer(&kr)))
	if errno != 0 {
		return errno
	}
	if int64(r) != int64(len(buf)) {
		return fmt.Errorf("kernel write short: got %d want %d", r, len(buf))
	}
	return nil
}

// processVM 后备读取 (root 下可读任意进程)
func processVMRead(pid int, addr uintptr, buf []byte) (int, error) {
	l := iovec{Base: unsafe.Pointer(&buf[0]), Len: uint64(len(buf))}
	r := iovec{Base: unsafe.Pointer(addr), Len: uint64(len(buf))}
	n, _, errno := syscall.Syscall6(SYS_PROCESS_VM_READV, uintptr(pid),
		uintptr(unsafe.Pointer(&l)), 1, uintptr(unsafe.Pointer(&r)), 1, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func processVMWrite(pid int, addr uintptr, buf []byte) (int, error) {
	l := iovec{Base: unsafe.Pointer(&buf[0]), Len: uint64(len(buf))}
	r := iovec{Base: unsafe.Pointer(addr), Len: uint64(len(buf))}
	n, _, errno := syscall.Syscall6(SYS_PROCESS_VM_WRITEV, uintptr(pid),
		uintptr(unsafe.Pointer(&l)), 1, uintptr(unsafe.Pointer(&r)), 1, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

var memFileCache = struct {
	sync.Mutex
	pid int
	f   *os.File
}{pid: -1}

func openMemFile(pid int) (*os.File, error) {
	memFileCache.Lock()
	defer memFileCache.Unlock()
	if memFileCache.pid == pid && memFileCache.f != nil {
		return memFileCache.f, nil
	}
	if memFileCache.f != nil {
		memFileCache.f.Close()
		memFileCache.f = nil
	}
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	memFileCache.pid = pid
	memFileCache.f = f
	return f, nil
}

// MemIO 内存访问器: 内核驱动 > process_vm > /proc/mem
type MemIO struct {
	Pid  int
	Kern *KernelMem
	Mode string // kernel | processvm | memfile
}

func (m *MemIO) ReadAt(addr uintptr, buf []byte) error {
	// 内核驱动优先(抗检测), 块大小64KB(v2.9.4: 4KB→64KB减少16倍syscall)
	if m.Kern != nil && m.Kern.ok {
		const chunk = 64 << 10
		off := 0
		for off < len(buf) {
			n := len(buf) - off
			if n > chunk {
				n = chunk
			}
			if err := m.Kern.kernelRead(m.Pid, addr+uintptr(off), buf[off:off+n]); err != nil {
				// 驱动失败则降级
				m.Kern = nil
				m.Mode = "fallback"
				return m.ReadAt(addr, buf)
			}
			off += n
		}
		if m.Mode == "" {
			m.Mode = "kernel"
		}
		return nil
	}
	// process_vm_readv, 块1MB
	const chunk2 = 1 << 20
	off := 0
	for off < len(buf) {
		n := len(buf) - off
		if n > chunk2 {
			n = chunk2
		}
		got, err := processVMRead(m.Pid, addr+uintptr(off), buf[off:off+n])
		if err != nil || got != n {
			return m.readMemFile(addr+uintptr(off), buf[off:off+n])
		}
		off += n
	}
	if m.Mode == "" {
		m.Mode = "processvm"
	}
	return nil
}

func (m *MemIO) readMemFile(addr uintptr, buf []byte) error {
	f, err := openMemFile(m.Pid)
	if err != nil {
		return err
	}
	n, err := f.ReadAt(buf, int64(addr))
	if err != nil && n != len(buf) {
		return err
	}
	m.Mode = "memfile"
	return nil
}

func (m *MemIO) WriteAt(addr uintptr, buf []byte) error {
	if m.Kern != nil && m.Kern.ok {
		const chunk = 4096
		off := 0
		for off < len(buf) {
			n := len(buf) - off
			if n > chunk {
				n = chunk
			}
			if err := m.Kern.kernelWrite(m.Pid, addr+uintptr(off), buf[off:off+n]); err != nil {
				m.Kern = nil
				return m.WriteAt(addr, buf)
			}
			off += n
		}
		return nil
	}
	// process_vm_writev
	const chunk2 = 1 << 20
	off := 0
	for off < len(buf) {
		n := len(buf) - off
		if n > chunk2 {
			n = chunk2
		}
		got, err := processVMWrite(m.Pid, addr+uintptr(off), buf[off:off+n])
		if err != nil || got != n {
			f, ferr := openMemFile(m.Pid)
			if ferr != nil {
				return ferr
			}
			if _, werr := f.WriteAt(buf[off:off+n], int64(addr+uintptr(off))); werr != nil {
				return werr
			}
		}
		off += n
	}
	return nil
}

// ---------- 类型系统 ----------
type MemType struct {
	Code int
	Name string
	Size int
}

var memTypes = []MemType{
	{1, "byte", 1}, {2, "word", 2}, {4, "dword", 4}, {8, "qword", 8},
	{16, "float", 4}, {32, "double", 8},
}

func typeByName(s string) (MemType, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "byte", "b", "1":
		return MemType{1, "byte", 1}, nil
	case "word", "w", "2":
		return MemType{2, "word", 2}, nil
	case "dword", "dw", "4":
		return MemType{4, "dword", 4}, nil
	case "qword", "qw", "8":
		return MemType{8, "qword", 8}, nil
	case "float", "f", "16":
		return MemType{16, "float", 4}, nil
	case "double", "d", "32":
		return MemType{32, "double", 8}, nil
	}
	return MemType{}, fmt.Errorf("unknown type: %s", s)
}

func parseValue(s string, t MemType) ([]byte, error) {
	var v uint64
	isFloat := t.Code == 16 || t.Code == 32
	trim := strings.TrimSpace(s)
	if strings.HasPrefix(trim, "0x") || strings.HasPrefix(trim, "0X") {
		x, err := strconv.ParseUint(trim[2:], 16, 64)
		if err != nil {
			return nil, err
		}
		v = x
	} else if isFloat {
		f, err := strconv.ParseFloat(trim, 64)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 8)
		if t.Code == 16 {
			binary.LittleEndian.PutUint32(buf, float32bits(float32(f)))
			return buf[:4], nil
		}
		binary.LittleEndian.PutUint64(buf, float64bits(f))
		return buf, nil
	} else {
		x, err := strconv.ParseUint(trim, 10, 64)
		if err != nil {
			// 支持负数
			n, err2 := strconv.ParseInt(trim, 10, 64)
			if err2 != nil {
				return nil, err
			}
			v = uint64(n)
		} else {
			v = x
		}
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	return buf[:t.Size], nil
}

func float32bits(f float32) uint32 { return *(*uint32)(unsafe.Pointer(&f)) }
func float64bits(f float64) uint64 { return *(*uint64)(unsafe.Pointer(&f)) }
func float32frombits(b uint32) float32 { return *(*float32)(unsafe.Pointer(&b)) }
func float64frombits(b uint64) float64 { return *(*float64)(unsafe.Pointer(&b)) }

// 值渲染
func renderValue(buf []byte, t MemType) string {
	switch t.Code {
	case 1:
		return strconv.FormatUint(uint64(buf[0]), 10)
	case 2:
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint16(buf)), 10)
	case 4:
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(buf)), 10)
	case 8:
		return strconv.FormatUint(binary.LittleEndian.Uint64(buf), 10)
	case 16:
		return strconv.FormatFloat(float64(float32frombits(binary.LittleEndian.Uint32(buf))), 'f', -1, 32)
	case 32:
		return strconv.FormatFloat(float64frombits(binary.LittleEndian.Uint64(buf)), 'f', -1, 64)
	}
	return ""
}

func renderHex(buf []byte) string {
	var sb strings.Builder
	for _, b := range buf {
		sb.WriteString(fmt.Sprintf("%02x", b))
	}
	return sb.String()
}

// ---------- 进程 & maps ----------
type ProcInfo struct {
	Pid      int    `json:"pid"`
	Name     string `json:"name"`
	Cmdline  string `json:"cmdline"`
	Uid      string `json:"uid"`
	Arch     string `json:"arch"`
	Rss      string `json:"rss"`
}

type MapSeg struct {
	Start  uintptr `json:"start"`
	End    uintptr `json:"end"`
	Prot   string  `json:"prot"`
	Offset uint64  `json:"offset"`
	Path   string  `json:"path"`
}

// listProcesses 枚举进程, 返回带排序的完整列表(筛选由handler按需执行)
// includeKernel: true=包含内核线程; appOnly: true=仅应用进程(uid>=10000)
// sortMode: active(默认,应用优先+活跃度) | pid | adj(活跃度) | name
func listProcesses(includeKernel, appOnly bool, sortMode string) ([]ProcInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	type ps struct {
		info ProcInfo
		adj  int  // oom_score_adj: 越小越活跃(前台0/负值, 后台100+)
		kern bool // 内核线程标记
	}
	var out []ps
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		cmd := strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " "))
		stat, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		ppid := 0
		if i := strings.LastIndex(string(stat), ")"); i >= 0 {
			f := strings.Fields(string(stat)[i+1:])
			if len(f) >= 2 {
				ppid, _ = strconv.Atoi(f[1])
			}
		}
		status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		var name, uid, rss string
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Name:") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "Uid:") {
				if f := strings.Fields(line); len(f) > 1 {
					uid = f[1]
				}
			}
			if strings.HasPrefix(line, "VmRSS:") {
				rss = strings.TrimSpace(strings.TrimPrefix(line, "VmRSS:"))
			}
		}
		// 内核线程: 父进程是kthreadd(pid=2) 或 cmdline/status都读不到
		kern := ppid == 2 || (cmd == "" && name == "")
		if name == "" {
			name = cmd
		}
		// 筛选: 排除内核线程 / 仅应用
		if !includeKernel && kern {
			continue
		}
		if appOnly && !isAppUid(uid) {
			continue
		}
		// 活跃度: oom_score_adj 读取失败给默认值999(排最后)
		adj := 999
		if ab, err := os.ReadFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid)); err == nil {
			if v, err := strconv.Atoi(strings.TrimSpace(string(ab))); err == nil {
				adj = v
			}
		}
		out = append(out, ps{ProcInfo{Pid: pid, Name: name, Cmdline: cmd, Uid: uid, Rss: rss}, adj, kern})
	}
	// 排序模式
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch sortMode {
		case "pid":
			return a.info.Pid < b.info.Pid
		case "adj":
			if a.adj != b.adj {
				return a.adj < b.adj
			}
			return a.info.Pid < b.info.Pid
		case "name":
			if a.info.Name != b.info.Name {
				return a.info.Name < b.info.Name
			}
			return a.info.Pid < b.info.Pid
		default: // active: 应用优先 → 活跃度 → pid
			if a.kern != b.kern {
				return !a.kern
			}
			ai, bi := isAppUid(a.info.Uid), isAppUid(b.info.Uid)
			if ai != bi {
				return ai
			}
			if a.adj != b.adj {
				return a.adj < b.adj
			}
			return a.info.Pid < b.info.Pid
		}
	})
	res := make([]ProcInfo, len(out))
	for i := range out {
		res[i] = out[i].info
	}
	return res, nil
}

func isAppUid(u string) bool {
	n, err := strconv.Atoi(u)
	return err == nil && n >= 10000
}

func readMaps(pid int) ([]MapSeg, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	var segs []MapSeg
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		parts := strings.Split(fields[0], "-")
		if len(parts) != 2 {
			continue
		}
		start, e1 := strconv.ParseUint(parts[0], 16, 64)
		end, e2 := strconv.ParseUint(parts[1], 16, 64)
		off, e3 := strconv.ParseUint(fields[2], 16, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		path := ""
		if len(fields) >= 6 {
			path = fields[5]
		}
		segs = append(segs, MapSeg{Start: uintptr(start), End: uintptr(end), Prot: fields[1], Offset: off, Path: path})
	}
	return segs, nil
}

func moduleBase(segs []MapSeg, name string) uintptr {
	// 匹配路径末尾
	for _, s := range segs {
		if s.Path != "" && (strings.HasSuffix(s.Path, "/"+name) || s.Path == name) {
			return s.Start
		}
	}
	return 0
}

// 搜索区域选择
func selectSegments(segs []MapSeg, region string, rstart, rend uintptr) []MapSeg {
	var out []MapSeg
	for _, s := range segs {
		if s.Prot == "" || !strings.Contains(s.Prot, "r") {
			continue
		}
		// 跳过不可读
		if rstart != 0 && s.End <= rstart {
			continue
		}
		if rend != 0 && s.Start >= rend {
			continue
		}
		lo, hi := s.Start, s.End
		if rstart != 0 && lo < rstart {
			lo = rstart
		}
		if rend != 0 && hi > rend {
			hi = rend
		}
		if lo >= hi {
			continue
		}
		switch region {
		case "heap":
			if !isHeapSeg(s) {
				continue
			}
		case "stack":
			if !isStackSeg(s) {
				continue
			}
		case "anonymous":
			if s.Path != "" {
				continue
			}
		case "module":
			if s.Path == "" {
				continue
			}
		}
		ns := s
		ns.Start, ns.End = lo, hi
		out = append(out, ns)
	}
	return out
}

func isHeapSeg(s MapSeg) bool {
	// 必须可读
	if s.Prot == "" || !strings.Contains(s.Prot, "r") {
		return false
	}
	// 排除可执行段
	if strings.Contains(s.Prot, "x") {
		return false
	}
	// 排除内核高位地址
	if s.Start >= 0x800000000000 {
		return false
	}
	// 匿名段: 纯匿名(Path为空) 或 Android命名匿名段([anon:xxx])
	// 注意: Android的ART/Unity活跃堆是[anon:dalvik-main space]等带名匿名段
	isAnon := s.Path == "" || strings.HasPrefix(s.Path, "[anon:")
	if !isAnon {
		return false
	}
	// 排除设备映射(防御)
	if strings.Contains(s.Path, "/dev/") {
		return false
	}
	return true
}
func isStackSeg(s MapSeg) bool {
	return strings.Contains(s.Path, "[stack]")
}

// ---------- 搜索状态 ----------
type SearchState struct {
	Pid        int
	Type       MemType
	Aligned    bool
	Candidates []uintptr // 精确搜索结果地址
	Bitmap     []uint8   // 模糊搜索位图
	Segs       []MapSeg  // 当前扫描段
	Snapshots  [][]byte  // 模糊搜索每段快照(上一次扫描的原始数据)
	FuzzyInit  bool
	Truncated  bool  // 快照因内存上限被截断(部分区域未纳入比较)
	XorKey     *uint32 // Xor搜索的密钥(众数K)
}

// ---------- 全局配置(可持久化, 通过 gg_config_set 动态调整) ----------
type Config struct {
	SearchMaxResults   int `json:"searchMaxResults"`   // 返回给用户的最大结果数(0=无限制, 只影响显示不影响候选收集)
	SearchCandidateMax int `json:"searchCandidateMax"` // 候选全量上限(内存保护, 0=无限; 默认500万≈40MB)
	FuzzyMaxSnapshotMB int `json:"fuzzyMaxSnapshotMB"` // 模糊搜索快照上限MB
	FreezeIntervalMs   int `json:"freezeIntervalMs"`   // 冻结写入间隔ms
	ListDefaultLimit   int `json:"listDefaultLimit"`   // 进程列表默认条数
	ListMaxLimit       int `json:"listMaxLimit"`       // 进程列表最大条数
	ResultsDefaultLimit int `json:"resultsDefaultLimit"` // 结果查看默认条数
	ResultsMaxLimit    int `json:"resultsMaxLimit"`    // 结果查看最大条数
	SetAllMax          int `json:"setAllMax"`          // 一键全改最大地址数
}

func DefaultConfig() *Config {
	return &Config{
		SearchMaxResults:   100000,
		SearchCandidateMax: 5000000,
		FuzzyMaxSnapshotMB: 512,
		FreezeIntervalMs:   50,
		ListDefaultLimit:   100,
		ListMaxLimit:       1000,
		ResultsDefaultLimit: 50,
		ResultsMaxLimit:    1000,
		SetAllMax:          100000,
	}
}

var ConfigPath = "/data/local/tmp/ggmcp/config.json"

func LoadConfig() *Config {
	c := DefaultConfig()
	data, err := os.ReadFile(ConfigPath)
	if err != nil {
		return c
	}
	if json.Unmarshal(data, c) != nil {
		return c
	}
	// 合法性兜底
	if c.SearchMaxResults < 0 || c.SearchCandidateMax < 0 || c.FuzzyMaxSnapshotMB < 16 || c.FreezeIntervalMs < 5 ||
		c.ListDefaultLimit < 1 || c.ListMaxLimit < c.ListDefaultLimit ||
		c.ResultsDefaultLimit < 1 || c.ResultsMaxLimit < c.ResultsDefaultLimit ||
		c.SetAllMax < 1 {
		return DefaultConfig()
	}
	return c
}

func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath, data, 0644)
}

// 运行时配置(启动时加载, gg_config_set 可热更新并持久化)
var cfg = LoadConfig()

func MaxSnapshotBytes() uint64 {
	return uint64(cfg.FuzzyMaxSnapshotMB) << 20
}

type GGSession struct {
	mu        sync.Mutex
	Pid       int
	Kern      *KernelMem
	Mem       *MemIO
	Search    *SearchState
	Frozen    map[string]*FrozenEntry
	Truncated bool // 模糊搜索快照被截断标记
}

type FrozenEntry struct {
	Addr     uintptr
	Type     MemType
	Value    []byte
	Stop     chan struct{}
	Done     chan struct{} // goroutine退出时close, 解冻确认用
	stopOnce sync.Once     // 防重复close panic
}

// StopFreeze 安全停止冻结(可重复调用, 不panic)
func (f *FrozenEntry) StopFreeze() { f.stopOnce.Do(func() { close(f.Stop) }) }

// WaitDone 等待冻结goroutine真正退出, 超时返回false
func (f *FrozenEntry) WaitDone(timeout time.Duration) bool {
	select {
	case <-f.Done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// 位图操作
func bmGet(bm []uint8, idx uint64) bool { return bm[idx/8]&(1<<(idx%8)) != 0 }
func bmSet(bm []uint8, idx uint64)       { bm[idx/8] |= 1 << (idx%8) }
func bmClear(bm []uint8, idx uint64)     { bm[idx/8] &^= 1 << (idx%8) }

// 对齐
func alignUp(a uintptr, n int) uintptr { return (a + uintptr(n) - 1) &^ uintptr(n-1) }
func alignDown(a uintptr, n int) uintptr { return a &^ uintptr(n-1) }

// ExactSearch 精确搜索
// ExactSearch 精确搜索(结果数受cfg.SearchMaxResults限制, 0=无限制)
// splitSegsByBytes 按累计字节数把段分片给N个worker(负载均衡)
func splitSegsByBytes(segs []MapSeg, workers int) [][2]int {
	if len(segs) == 0 || workers <= 1 {
		return [][2]int{{0, len(segs)}}
	}
	var total uint64
	for _, sg := range segs {
		total += uint64(sg.End - sg.Start)
	}
	per := total / uint64(workers)
	if per == 0 {
		per = 1
	}
	chunks := make([][2]int, 0, workers)
	cur := 0
	var acc uint64
	for i, sg := range segs {
		acc += uint64(sg.End - sg.Start)
		if acc >= per && len(chunks) < workers-1 {
			chunks = append(chunks, [2]int{cur, i + 1})
			cur = i + 1
			acc = 0
		}
	}
	chunks = append(chunks, [2]int{cur, len(segs)})
	return chunks
}

// ExactSearch 精确搜索: 多线程并行 + 全量候选收集(不截断)
// 返回值: (候选数, 是否因searchCandidateMax截断, error)
// 设计: 候选全量保留(几百万地址≈几十MB), searchMaxResults只限制"返回显示", 不再漏真身
func (s *GGSession) ExactSearch(value []byte, t MemType, region string, rstart, rend uintptr, aligned bool) (int, bool, error) {
	segs, err := readMaps(s.Pid)
	if err != nil {
		return 0, false, err
	}
	segs = selectSegments(segs, region, rstart, rend)
	align := 1
	if aligned {
		align = t.Size
	}
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	chunks := splitSegsByBytes(segs, workers)
	results := make([][]uintptr, len(chunks))
	var wg sync.WaitGroup
	for w, cr := range chunks {
		wg.Add(1)
		go func(w int, cr [2]int) {
			defer wg.Done()
			mio := newMemIO(s.Pid)
			defer func() {
				if mio.Kern != nil {
					mio.Kern.Close()
				}
			}()
			var found []uintptr
			buf := make([]byte, 64*1024)
			for si := cr[0]; si < cr[1]; si++ {
				seg := segs[si]
				// 起始对齐
				addr := seg.Start
				if aligned {
					addr = alignUp(addr, align)
				}
				for addr+uintptr(len(buf)) <= seg.End {
					if mio.ReadAt(addr, buf) != nil {
						break
					}
					scanBuf(buf, value, t.Size, addr, aligned, &found)
					addr += uintptr(len(buf))
				}
				// 尾巴
				if addr < seg.End {
					rest := int(seg.End - addr)
					if rest > 0 {
						rbuf := make([]byte, rest)
						if mio.ReadAt(addr, rbuf) == nil {
							scanBuf(rbuf, value, t.Size, addr, aligned, &found)
						}
					}
				}
			}
			results[w] = found
		}(w, cr)
	}
	wg.Wait()
	// 合并全量候选(不截断, 上限只用于内存保护且可配置)
	var total int
	for _, r := range results {
		total += len(r)
	}
	found := make([]uintptr, 0, total)
	for _, r := range results {
		found = append(found, r...)
	}
	truncated := false
	if cfg.SearchCandidateMax > 0 && len(found) > cfg.SearchCandidateMax {
		found = found[:cfg.SearchCandidateMax]
		truncated = true
	}
	s.Search = &SearchState{
		Pid: s.Pid, Type: t, Aligned: aligned, Candidates: found,
		Segs: segs,
	}
	return len(found), truncated, nil
}
func scanBuf(buf []byte, value []byte, tsize int, base uintptr, aligned bool, found *[]uintptr) {
	step := 1
	if aligned {
		step = tsize
	}
	limit := len(buf) - tsize + 1
	for i := 0; i < limit; i += step {
		if bytes.Equal(buf[i:i+tsize], value) {
			*found = append(*found, base+uintptr(i))
		}
	}
}

// FuzzyInit 模糊搜索初始化: 读取全部段数据作为快照, 候选位图全置1
func (s *GGSession) FuzzyInit(t MemType, region string, rstart, rend uintptr) (uint64, error) {
	segs, err := readMaps(s.Pid)
	if err != nil {
		return 0, err
	}
	segs = selectSegments(segs, region, rstart, rend)
	align := t.Size
	var bits uint64
	for _, seg := range segs {
		bits += (uint64(seg.End-seg.Start) / uint64(align)) + 1
	}
	bm := make([]uint8, (bits+7)/8)
	for i := range bm {
		bm[i] = 0xFF
	}
	// 尾部清零: 只清最后一个字节里超出实际slot的高位(避免越界)
	lastByte := bits / 8
	lastBit := bits % 8
	if lastBit != 0 {
		for i := lastBit; i < 8; i++ {
			bm[lastByte] &^= 1 << i
		}
	}
	// 读快照(带内存上限保护: 超过上限的部分截断, 避免内存炸弹; 上限可通过gg_config_set调整)
	// v2.9.3策略: 超大段(>上限80%, 如dalvik region space 512MB)跳过不占额度,
	// 优先保证native小段(libc_malloc等游戏数据段)完整读入 — 否则大段占满上限会导致后续段全漏
	// v2.9.4: 快照读取多线程化(按段分片, 每worker独立socket), 512MB快照从分钟级降到秒级
	s.Truncated = false
	snaps := make([][]byte, len(segs))
	var snapTotal uint64
	maxSnap := MaxSnapshotBytes()
	for i, seg := range segs {
		sz := uint64(seg.End - seg.Start)
		if sz > maxSnap*4/5 {
			s.Truncated = true // 超大段跳过(标记, 不占额度)
			snaps[i] = nil
			continue
		}
		if snapTotal+sz > maxSnap {
			sz = maxSnap - snapTotal // 截断到剩余额度
			s.Truncated = true
		}
		if sz <= 0 {
			snaps[i] = nil
			continue
		}
		snaps[i] = make([]byte, int(sz))
		snapTotal += sz
	}
	// 并行读取快照: 每worker独立socket, 按字节分片负载均衡
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	chunks := splitSegsByBytes(segs, workers)
	var wg sync.WaitGroup
	for w, cr := range chunks {
		wg.Add(1)
		go func(w int, cr [2]int) {
			defer wg.Done()
			mio := newMemIO(s.Pid)
			defer func() {
				if mio.Kern != nil {
					mio.Kern.Close()
				}
			}()
			for si := cr[0]; si < cr[1]; si++ {
				if snaps[si] == nil {
					continue
				}
				if mio.ReadAt(segs[si].Start, snaps[si]) != nil {
					// 读失败段标记为空快照(该段候选会在refine时被剔除)
					snaps[si] = nil
				}
			}
		}(w, cr)
	}
	wg.Wait()
	s.Search = &SearchState{
		Pid: s.Pid, Type: t, Aligned: true, Bitmap: bm, Segs: segs,
		Snapshots: snaps, FuzzyInit: true,
	}
	return bits, nil
}

// FuzzyRefine 模糊细化: 与上一次快照比较, mode=increased/decreased/unchanged/changed
// v2.9.4: 多线程并行(按段分片, 每worker独立socket + 局部位图, 最后合并)
func (s *GGSession) FuzzyRefine(mode string, minV, maxV, minAbs *float64) (uint64, error) {
	if s.Search == nil || !s.Search.FuzzyInit {
		return 0, errors.New("no fuzzy search initialized")
	}
	align := s.Search.Type.Size
	bm := s.Search.Bitmap
	segs := s.Search.Segs
	snaps := s.Search.Snapshots
	keep := make([]uint8, len(bm))
	// 预计算每段的bit起始(避免循环内重复O(n)计算)
	baseOf := make([]uint64, len(segs)+1)
	for si := range segs {
		baseOf[si] = segIdxBase(si, segs, align)
	}
	baseOf[len(segs)] = segIdxBase(len(segs), segs, align)
	// 按字节分片并行比较
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	chunks := splitSegsByBytes(segs, workers)
	type chunkKeep struct {
		start uint64 // 全局bit起始
		data  []uint8
	}
	keeps := make([]chunkKeep, len(chunks))
	var wg sync.WaitGroup
	for w, cr := range chunks {
		wg.Add(1)
		go func(w int, cr [2]int) {
			defer wg.Done()
			if cr[0] >= cr[1] {
				return
			}
			bitStart := baseOf[cr[0]]
			bitEnd := baseOf[cr[1]]
			local := make([]uint8, (bitEnd-bitStart+7)/8)
			mio := newMemIO(s.Pid)
			defer func() {
				if mio.Kern != nil {
					mio.Kern.Close()
				}
			}()
			segCache := make([]byte, 64*1024)
			for si := cr[0]; si < cr[1]; si++ {
				seg := segs[si]
				snap := snaps[si]
				if snap == nil {
					continue
				}
				base := baseOf[si]
				addr := seg.Start
				for addr < seg.End {
					n := uintptr(len(segCache))
					if addr+n > seg.End {
						n = seg.End - addr
					}
					if mio.ReadAt(addr, segCache[:n]) != nil {
						break
					}
					// 遍历块内对齐slot(段首不要求按align对齐, slot从段起点开始)
					for off := uintptr(0); off+uintptr(align) <= n; off += uintptr(align) {
						rel := addr + off - seg.Start
						slotIdx := base + uint64(rel)/uint64(align)
						if !(slotIdx < uint64(len(bm))*8 && bmGet(bm, slotIdx)) {
							continue
						}
						// 快照中的旧值(注意快照长度可能不足, 处理越界)
						if int(rel)+align > len(snap) {
							continue
						}
						old := snap[rel : rel+uintptr(align)]
						cur := segCache[off : off+uintptr(align)]
						if matchFuzzy(old, cur, mode, minV, maxV, minAbs) {
							bmSet(local, slotIdx-bitStart)
							// 更新快照为当前值(供下次比较)
							copy(old, cur)
						}
					}
					addr += n
				}
			}
			keeps[w] = chunkKeep{start: bitStart, data: local}
		}(w, cr)
	}
	wg.Wait()
	// 合并局部位图到全局(逐set bit)
	for _, ck := range keeps {
		if ck.data == nil {
			continue
		}
		for li, b := range ck.data {
			if b == 0 {
				continue
			}
			for bi := 0; bi < 8; bi++ {
				if b&(1<<uint(bi)) != 0 {
					gi := ck.start + uint64(li)*8 + uint64(bi)
					if gi < uint64(len(keep))*8 {
						bmSet(keep, gi)
					}
				}
			}
		}
	}
	s.Search.Bitmap = keep
	return countBits(keep), nil
}

func segIdxBase(si int, segs []MapSeg, align int) uint64 {
	var base uint64
	for i := 0; i < si; i++ {
		base += (uint64(segs[i].End-segs[i].Start) / uint64(align)) + 1
	}
	return base
}

func bytesToFloatVal(b []byte) float64 {
	switch len(b) {
	case 4:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(b)))
	case 8:
		return math.Float64frombits(binary.LittleEndian.Uint64(b))
	case 2:
		return float64(int16(binary.LittleEndian.Uint16(b)))
	case 1:
		return float64(int8(b[0]))
	}
	return 0
}

// matchFuzzy 模糊匹配, mode=increased/decreased/unchanged/changed/range
// range模式: 当前值在[minV,maxV]范围内则保留; minAbs: 最小绝对值过滤(剔除1e-17级垃圾值)
func matchFuzzy(old, cur []byte, mode string, minV, maxV, minAbs *float64) bool {
	if mode == "range" {
		if minV == nil && maxV == nil && minAbs == nil {
			return true
		}
		v := bytesToFloatVal(cur)
		if v != v { // NaN: 不满足任何范围条件, 直接剔除(否则NaN会漏过所有比较)
			return false
		}
		if minV != nil && v < *minV {
			return false
		}
		if maxV != nil && v > *maxV {
			return false
		}
		if minAbs != nil && math.Abs(v) < *minAbs {
			return false
		}
		return true
	}
	cmp := bytes.Compare(old, cur)
	switch mode {
	case "increased":
		return cmp < 0
	case "decreased":
		return cmp > 0
	case "unchanged":
		return cmp == 0
	case "changed":
		return cmp != 0
	}
	return false
}

func countBits(bm []uint8) uint64 {
	var c uint64
	for _, b := range bm {
		for i := 0; i < 8; i++ {
			if b&(1<<uint(i)) != 0 {
				c++
			}
		}
	}
	return c
}

// Refine 两步搜索核心: 在现有结果Candidates中读值过滤, 只保留值==value的地址
// 用法: 先gg_search当前值 → 游戏内让值变化 → Refine新值 → 命中缩到个位数
func (s *GGSession) Refine(value []byte, t MemType) (int, error) {
	if s.Search == nil || s.Search.FuzzyInit {
		return 0, errors.New("no exact search results to refine (先做精确搜索)")
	}
	if t.Size != s.Search.Type.Size {
		return 0, errors.New("refine类型大小必须与上次搜索一致")
	}
	var kept []uintptr
	buf := make([]byte, t.Size)
	for _, addr := range s.Search.Candidates {
		if s.Mem.ReadAt(addr, buf) != nil {
			continue
		}
		if bytes.Equal(buf, value) {
			kept = append(kept, addr)
		}
	}
	s.Search.Candidates = kept
	return len(kept), nil
}

// 收集模糊结果地址
func (s *GGSession) FuzzyResults(limit int) []uintptr {
	var out []uintptr
	align := s.Search.Type.Size
	for si, seg := range s.Search.Segs {
		base := segIdxBase(si, s.Search.Segs, align)
		n := (uint64(seg.End-seg.Start) / uint64(align)) + 1
		for j := uint64(0); j < n && len(out) < limit; j++ {
			idx := base + j
			if bmGet(s.Search.Bitmap, idx) {
				out = append(out, seg.Start+uintptr(j*uint64(align)))
			}
		}
		if len(out) >= limit {
			break
		}
	}
	return out
}

// ---------- Auto自动类型搜索(byte/word/dword/qword/float) + 多线程并行 ----------

type AutoTypeStat struct {
	Type  string `json:"type"`  // 类型名
	Count int    `json:"count"` // 该类型命中数
}

type AutoResult struct {
	Value     int            `json:"value"`     // 搜索值
	Types     []AutoTypeStat `json:"types"`     // 各类型命中统计(独立报告)
	Total     int            `json:"total"`     // 去重后总命中
	Samples   []string       `json:"samples"`   // 样例地址(前20)
	Tip       string         `json:"tip"`       // 提示
	Truncated bool           `json:"truncated"` // 候选超searchCandidateMax被截断
}

// newMemIO 创建独立的内存访问器(每个worker独立socket, 支持并行ioctl)
func newMemIO(pid int) *MemIO {
	k := &KernelMem{}
	if err := k.Init(); err == nil && k.ok {
		return &MemIO{Pid: pid, Kern: k}
	}
	return &MemIO{Pid: pid}
}

// AutoSearch 自动类型搜索: 对byte/word/dword/qword/float全部扫描
// v2.9优化: ①多线程按字节分片 ②各类型独立收集(不互相淹没) ③全量候选不截断
// 稀有类型优先保留: 候选超searchCandidateMax时按 qword>dword>float>word>byte 顺序截断
func (s *GGSession) AutoSearch(value int, region string, rstart, rend uintptr) (*AutoResult, error) {
	segs, err := readMaps(s.Pid)
	if err != nil {
		return nil, err
	}
	segs = selectSegments(segs, region, rstart, rend)
	if len(segs) == 0 {
		return &AutoResult{Value: value, Tip: "没有可扫描的内存段"}, nil
	}
	// 各类型目标字节
	val32 := uint32(value)
	val64 := uint64(value)
	targets := []struct {
		name string
		size int
		cmp  func(buf []byte, off int) bool
	}{
		{"byte", 1, func(b []byte, o int) bool { return b[o] == byte(value) }},
		{"word", 2, func(b []byte, o int) bool { return binary.LittleEndian.Uint16(b[o:]) == uint16(value) }},
		{"dword", 4, func(b []byte, o int) bool { return binary.LittleEndian.Uint32(b[o:]) == val32 }},
		{"float", 4, func(b []byte, o int) bool { return binary.LittleEndian.Uint32(b[o:]) == float32bits(float32(value)) }},
		{"qword", 8, func(b []byte, o int) bool { return binary.LittleEndian.Uint64(b[o:]) == val64 }},
	}
	// 按累计大小把段分给N个worker
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 2 {
		workers = 2
	}
	chunks := splitSegsByBytes(segs, workers)
	// 并发扫描: 每个worker独立socket + 独立按类型收集(无全局锁竞争)
	perWorker := make([][][]uintptr, len(chunks)) // [worker][type][]addr
	var wg sync.WaitGroup
	for w, cr := range chunks {
		wg.Add(1)
		go func(w int, cr [2]int) {
			defer wg.Done()
			mio := newMemIO(s.Pid)
			defer func() {
				if mio.Kern != nil {
					mio.Kern.Close()
				}
			}()
			local := make([][]uintptr, len(targets))
			buf := make([]byte, 64*1024)
			for si := cr[0]; si < cr[1]; si++ {
				sg := segs[si]
				addr := sg.Start
				for addr < sg.End {
					n := uintptr(len(buf))
					if addr+n > sg.End {
						n = sg.End - addr
					}
					if mio.ReadAt(addr, buf[:n]) != nil {
						break
					}
					for ti, tg := range targets {
						step := tg.size
						limitOff := int(n) - tg.size + 1
						for off := 0; off < limitOff; off += step {
							if tg.cmp(buf, off) {
								local[ti] = append(local[ti], addr+uintptr(off))
							}
						}
					}
					addr += n
				}
			}
			perWorker[w] = local
		}(w, cr)
	}
	wg.Wait()
	// 合并去重(按类型独立)
	typeAddrs := make([][]uintptr, len(targets))
	seen := make([]map[uintptr]bool, len(targets))
	for ti := range targets {
		seen[ti] = map[uintptr]bool{}
	}
	for _, local := range perWorker {
		for ti, addrs := range local {
			for _, a := range addrs {
				if !seen[ti][a] {
					seen[ti][a] = true
					typeAddrs[ti] = append(typeAddrs[ti], a)
				}
			}
		}
	}
	// 候选上限保护: 稀有类型优先保留(qword>dword>float>word>byte)
	// 与旧版区别: 不再让byte的450万挤爆池子淹没word/dword
	truncated := false
	if cfg.SearchCandidateMax > 0 {
		var total int
		for _, addrs := range typeAddrs {
			total += len(addrs)
		}
		if total > cfg.SearchCandidateMax {
			truncated = true
			remaining := cfg.SearchCandidateMax
			kept := make([][]uintptr, len(targets))
			for _, ti := range []int{4, 2, 3, 1, 0} { // qword,dword,float,word,byte
				addrs := typeAddrs[ti]
				if len(addrs) <= remaining {
					kept[ti] = addrs
					remaining -= len(addrs)
				} else {
					kept[ti] = addrs[:remaining]
					remaining = 0
					break
				}
			}
			typeAddrs = kept
		}
	}
	// 输出: 按类型独立报告
	res := &AutoResult{Value: value, Truncated: truncated}
	var all []uintptr
	for ti, tg := range targets {
		if len(typeAddrs[ti]) > 0 {
			res.Types = append(res.Types, AutoTypeStat{Type: tg.name, Count: len(typeAddrs[ti])})
		}
		all = append(all, typeAddrs[ti]...)
	}
	res.Total = len(all)
	for _, a := range all {
		if len(res.Samples) >= 20 {
			break
		}
		res.Samples = append(res.Samples, fmt.Sprintf("0x%x", a))
	}
	if res.Total == 0 {
		res.Tip = "未命中: 值可能加密/非标量存储, 试试gg_search_xor或模糊搜索"
	} else if len(res.Types) > 1 {
		res.Tip = "多类型命中(各类型独立统计), 用gg_get_results查看; 游戏内变值后refine锁定"
	} else {
		res.Tip = "单类型命中, 游戏内变值后refine锁定"
	}
	if truncated {
		res.Tip += "; 候选超searchCandidateMax已按稀有度截断, 可用gg_config_set调大"
	}
	// 保存候选(全量合并, 供refine使用)
	s.Search = &SearchState{
		Pid: s.Pid, Type: MemType{Name: "auto", Size: 4}, Aligned: false,
		Candidates: all, Segs: segs,
	}
	return res, nil
}

func uniqKeys(m map[uintptr]bool) []uintptr {
	out := make([]uintptr, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------- gg_watch 地址持续监控(坐标流/动态值检测) ----------

type WatchSample struct {
	TimeMs int64  `json:"t"`     // 相对监控开始的毫秒
	Addr   string `json:"addr"`  // 地址
	Value  string `json:"value"` // 当前值(按类型渲染)
	Hex    string `json:"hex"`   // 原始字节hex
}

type WatchAddrStat struct {
	Addr      string `json:"addr"`       // 地址
	Changes   int    `json:"changes"`    // 变化次数
	StartVal  string `json:"startValue"` // 起始值
	EndVal    string `json:"endValue"`   // 结束值
	Active    bool   `json:"active"`     // 是否在持续变化(动态值)
}

type WatchResult struct {
	Addrs      []string         `json:"addrs"`      // 监控的地址
	Type       string           `json:"type"`       // 类型
	DurationMs int64            `json:"durationMs"` // 监控时长
	IntervalMs int64            `json:"intervalMs"` // 采样间隔
	Changes    []WatchSample    `json:"changes"`    // 变化记录(onlyChanges=true时)
	Stats      []WatchAddrStat  `json:"stats"`      // 每地址统计
}

// WatchAddrs 持续监控一组地址的值变化(坐标流数据源)
// durationMs: 监控总时长; intervalMs: 采样间隔; onlyChanges: 只记录变化(默认true)
func (s *GGSession) WatchAddrs(addrs []uintptr, t MemType, durationMs, intervalMs int64, onlyChanges bool) (*WatchResult, error) {
	if len(addrs) == 0 {
		return nil, errors.New("addresses 不能为空")
	}
	if durationMs <= 0 {
		durationMs = 3000
	}
	if intervalMs < 10 {
		intervalMs = 100
	}
	res := &WatchResult{
		Type:       t.Name,
		DurationMs: durationMs,
		IntervalMs: intervalMs,
		Stats:      make([]WatchAddrStat, len(addrs)),
	}
	for i, a := range addrs {
		res.Addrs = append(res.Addrs, fmt.Sprintf("0x%x", a))
		res.Stats[i].Addr = fmt.Sprintf("0x%x", a)
	}
	start := time.Now()
	prev := make([][]byte, len(addrs))
	for i := range prev {
		prev[i] = make([]byte, t.Size)
	}
	first := true
	for time.Since(start) < time.Duration(durationMs)*time.Millisecond {
		for i, a := range addrs {
			buf := make([]byte, t.Size)
			if s.Mem.ReadAt(a, buf) != nil {
				continue // 读取失败跳过(地址可能已失效)
			}
			changed := first || !bytes.Equal(buf, prev[i])
			if changed {
				cur := renderValue(buf, t)
				if first {
					res.Stats[i].StartVal = cur
				}
				res.Stats[i].Changes++
				res.Stats[i].EndVal = cur
				if onlyChanges {
					res.Changes = append(res.Changes, WatchSample{
						TimeMs: time.Since(start).Milliseconds(),
						Addr:   fmt.Sprintf("0x%x", a),
						Value:  cur,
						Hex:    renderHex(buf),
					})
				}
			}
			copy(prev[i], buf)
		}
		first = false
		time.Sleep(time.Duration(intervalMs) * time.Millisecond)
	}
	// 动态判定: 变化次数>=3 且 起止值不同 = 活跃动态值
	for i := range res.Stats {
		res.Stats[i].Active = res.Stats[i].Changes >= 3 && res.Stats[i].StartVal != res.Stats[i].EndVal
	}
	return res, nil
}

// Close 关闭内核通道
func (k *KernelMem) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fd > 0 {
		syscall.Close(k.fd)
		k.fd = 0
	}
	k.ok = false
}

type XorKeyStat struct {
	Key   uint32   `json:"key"`   // 密钥K = 内容 XOR 搜索值
	Count int      `json:"count"` // 命中该K的地址数
	Pct   float64  `json:"pct"`   // 占比%
	Addrs []string `json:"addrs"` // 样例地址(最多5个)
}

type XorResult struct {
	Value      string       `json:"value"`      // 搜索的明文值
	Scanned    int          `json:"scanned"`    // 扫描到的总候选数(所有K)
	Keys       []XorKeyStat `json:"keys"`       // K分布TOP20(众数=最可能的密钥)
	BestKey    uint32       `json:"bestKey"`    // 众数K
	BestCount  int          `json:"bestCount"`  // 众数K的地址数
	Refined    bool         `json:"refined"`    // 是否refine模式
	RefineKeep int          `json:"refineKeep"` // refine后保留数
	Tip        string       `json:"tip"`        // 使用提示
}

// XorSearch 加密值搜索:
// 1) 全内存扫描, 对每个对齐值计算 K = content XOR value
// 2) 统计K分布: 出现最多的K就是最可能的加密密钥(真身地址共享同一密钥)
// 3) 把K=众数的地址设为候选; refine=true时在现有候选中找K2==XorKey的(游戏变值后再搜)
func (s *GGSession) XorSearch(value []byte, t MemType, region string, rstart, rend uintptr, refine bool) (*XorResult, error) {
	if t.Size != 4 && t.Size != 8 {
		return nil, errors.New("Xor搜索仅支持 dword/qword(4/8字节)")
	}
	res := &XorResult{Value: renderValue(value, t), Refined: refine}
	if refine {
		// refine模式: 在现有候选中找 K2 == XorKey 的
		if s.Search == nil || s.Search.FuzzyInit || s.Search.XorKey == nil {
			return nil, errors.New("refine需要先做一次Xor搜索")
		}
		var keep []uintptr
		buf := make([]byte, t.Size)
		for _, a := range s.Search.Candidates {
			if s.Mem.ReadAt(a, buf) != nil {
				continue
			}
			var k uint32
			if t.Size == 4 {
				k = binary.LittleEndian.Uint32(buf) ^ binary.LittleEndian.Uint32(value)
			} else {
				k = uint32(binary.LittleEndian.Uint64(buf) ^ binary.LittleEndian.Uint64(value))
			}
			if k == *s.Search.XorKey {
				keep = append(keep, a)
			}
		}
		s.Search.Candidates = keep
		res.RefineKeep = len(keep)
		res.BestKey = *s.Search.XorKey
		if len(keep) == 0 {
			res.Tip = "0个保留: 密钥可能变了或真身不在候选, 建议重新Xor搜索"
		} else {
			res.Tip = "K=密钥不变的地址已保留, 用 gg_get_results 查看 / gg_set_results 修改(改值时需按 明文XOR密钥 写入)"
		}
		return res, nil
	}
	// 全扫描
	segs, err := readMaps(s.Pid)
	if err != nil {
		return nil, err
	}
	segs = selectSegments(segs, region, rstart, rend)
	align := t.Size
	kCount := map[uint32]int{}
	kSamples := map[uint32][]uintptr{}
	buf := make([]byte, 64*1024)
	for _, seg := range segs {
		addr := alignUp(seg.Start, align)
		for addr+uintptr(len(buf)) <= seg.End {
			if s.Mem.ReadAt(addr, buf) != nil {
				break
			}
			for off := 0; off+align <= len(buf); off += align {
				var k uint32
				if t.Size == 4 {
					k = binary.LittleEndian.Uint32(buf[off:]) ^ binary.LittleEndian.Uint32(value)
				} else {
					k = uint32(binary.LittleEndian.Uint64(buf[off:]) ^ binary.LittleEndian.Uint64(value))
				}
				kCount[k]++
				if len(kSamples[k]) < 5 {
					kSamples[k] = append(kSamples[k], addr+uintptr(off))
				}
			}
			addr += uintptr(len(buf))
		}
	}
	total := 0
	for _, n := range kCount {
		total += n
	}
	res.Scanned = total
	type ks struct {
		k uint32
		n int
	}
	arr := make([]ks, 0, len(kCount))
	for k, n := range kCount {
		arr = append(arr, ks{k, n})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].n != arr[j].n {
			return arr[i].n > arr[j].n
		}
		return arr[i].k < arr[j].k
	})
	if len(arr) > 20 {
		arr = arr[:20]
	}
	for _, a := range arr {
		sts := XorKeyStat{Key: a.k, Count: a.n, Pct: float64(a.n) * 100 / float64(total)}
		for _, ad := range kSamples[a.k] {
			sts.Addrs = append(sts.Addrs, fmt.Sprintf("0x%x", ad))
		}
		res.Keys = append(res.Keys, sts)
	}
	if len(arr) > 0 {
		res.BestKey = arr[0].k
		res.BestCount = arr[0].n
		// 候选 = 众数K的地址(可能还有其他高频K, 但先取众数)
		cands := kSamples[res.BestKey]
		// 重新收集众数K的全部地址
		var all []uintptr
		for _, seg := range segs {
			addr := alignUp(seg.Start, align)
			for addr+uintptr(len(buf)) <= seg.End {
				if s.Mem.ReadAt(addr, buf) != nil {
					break
				}
				for off := 0; off+align <= len(buf); off += align {
					var k uint32
					if t.Size == 4 {
						k = binary.LittleEndian.Uint32(buf[off:]) ^ binary.LittleEndian.Uint32(value)
					} else {
						k = uint32(binary.LittleEndian.Uint64(buf[off:]) ^ binary.LittleEndian.Uint64(value))
					}
					if k == res.BestKey {
						all = append(all, addr+uintptr(off))
						if len(all) >= cfg.SearchMaxResults {
							break
						}
					}
				}
				if len(all) >= cfg.SearchMaxResults {
					break
				}
				addr += uintptr(len(buf))
			}
			if len(all) >= cfg.SearchMaxResults {
				break
			}
		}
		s.Search = &SearchState{
			Pid: s.Pid, Type: t, Aligned: true, Candidates: all,
			Segs: segs, XorKey: &res.BestKey,
		}
		_ = cands
		res.Tip = fmt.Sprintf("最佳密钥K=0x%x (%d个地址)。游戏内变值后再次 Xor搜索新值+refine=true, K不变的地址即真身", res.BestKey, len(all))
	}
	return res, nil
}

type ResultSnapshot struct {
	ID        string   `json:"id"`        // 快照名
	Pid       int      `json:"pid"`       // 目标进程
	Type      string   `json:"type"`      // 值类型
	Source    string   `json:"source"`    // 来源(搜索值/描述)
	CreatedAt int64    `json:"createdAt"` // 创建时间戳
	Addrs     []uint64 `json:"addrs"`     // 地址列表
	Values    []string `json:"values"`    // 对应值(读取时快照, 供离线查看)
}

var SnapshotDir = "/data/local/tmp/ggmcp/snapshots"

// SaveSnapshot 将当前搜索结果保存为命名快照(持久化到磁盘)
// id: 快照名; source: 来源描述(如"攻击力搜索")
func (s *GGSession) SaveSnapshot(id, source string) (*ResultSnapshot, error) {
	if s.Search == nil {
		return nil, errors.New("没有搜索结果")
	}
	if id == "" {
		id = fmt.Sprintf("snap_%d", time.Now().Unix())
	}
	var addrs []uintptr
	if s.Search.FuzzyInit {
		addrs = s.FuzzyResults(cfg.SetAllMax)
	} else {
		addrs = s.Search.Candidates
	}
	t := s.Search.Type
	vals := make([]string, len(addrs))
	buf := make([]byte, t.Size)
	for i, a := range addrs {
		if s.Mem.ReadAt(a, buf) == nil {
			vals[i] = renderValue(buf, t)
		} else {
			vals[i] = "?"
		}
	}
	snap := &ResultSnapshot{
		ID: id, Pid: s.Pid, Type: t.Name, Source: source,
		CreatedAt: time.Now().Unix(),
		Addrs:     make([]uint64, len(addrs)),
		Values:    vals,
	}
	for i, a := range addrs {
		snap.Addrs[i] = uint64(a)
	}
	// 持久化
	if err := os.MkdirAll(SnapshotDir, 0755); err == nil {
		if data, err := json.MarshalIndent(snap, "", "  "); err == nil {
			os.WriteFile(fmt.Sprintf("%s/%s.json", SnapshotDir, id), data, 0644)
		}
	}
	return snap, nil
}

// LoadSnapshot 从磁盘加载快照
func LoadSnapshot(id string) (*ResultSnapshot, error) {
	data, err := os.ReadFile(fmt.Sprintf("%s/%s.json", SnapshotDir, id))
	if err != nil {
		return nil, err
	}
	var snap ResultSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// ListSnapshots 列出磁盘上的所有快照
func ListSnapshots() ([]ResultSnapshot, error) {
	entries, err := os.ReadDir(SnapshotDir)
	if err != nil {
		return nil, err
	}
	var out []ResultSnapshot
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if snap, err := LoadSnapshot(strings.TrimSuffix(name, ".json")); err == nil {
			out = append(out, *snap)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

func (s *ResultSnapshot) AddrSet() map[uint64]bool {
	m := make(map[uint64]bool, len(s.Addrs))
	for _, a := range s.Addrs {
		m[a] = true
	}
	return m
}

type CrossResult struct {
	SnapA      string         `json:"snapA"`      // 结果集A(快照名或"current")
	SnapB      string         `json:"snapB"`      // 结果集B
	CountA     int            `json:"countA"`     // A数量
	CountB     int            `json:"countB"`     // B数量
	Intersect  []string       `json:"intersect"`  // 交集地址(两结果共有)
	OnlyA      int            `json:"onlyA"`      // 仅A有的数量
	OnlyB      int            `json:"onlyB"`      // 仅B有的数量
	Adjacent   []AdjacentPair `json:"adjacent"`   // A与B地址相邻对(间隔<=gap)
	SameValue  int            `json:"sameValue"`  // 交集且值相同的数量
	RangeNotes []string       `json:"rangeNotes"` // 区间分布备注
}

// CrossAnalyze 交叉分析两个结果集: A=snapA(或当前), B=snapB(或当前)
// 支持: 交集 / 仅A / 仅B / 地址相邻对(结构体特征) / 同值交集
func (s *GGSession) CrossAnalyze(snapA, snapB string, gap uint64, useCurrentA, useCurrentB bool) (*CrossResult, error) {
	load := func(id string) (*ResultSnapshot, error) {
		return LoadSnapshot(id)
	}
	current := func() *ResultSnapshot {
		if s.Search == nil {
			return nil
		}
		snap, err := s.SaveSnapshot("", "current")
		if err != nil {
			return nil
		}
		return snap
	}
	var A, B *ResultSnapshot
	var err error
	if useCurrentA {
		A = current()
	} else {
		A, err = load(snapA)
	}
	if err != nil || A == nil {
		return nil, fmt.Errorf("快照A不可用: %v (先用 gg_snapshot_results 保存)", err)
	}
	if useCurrentB {
		B = current()
	} else {
		B, err = load(snapB)
	}
	if err != nil || B == nil {
		return nil, fmt.Errorf("快照B不可用: %v (先用 gg_snapshot_results 保存)", err)
	}
	res := &CrossResult{
		SnapA: snapA, SnapB: snapB, CountA: len(A.Addrs), CountB: len(B.Addrs),
	}
	setA := A.AddrSet()
	setB := B.AddrSet()
	// 交集 + 同值 + 仅A/仅B
	for _, a := range A.Addrs {
		if setB[a] {
			res.Intersect = append(res.Intersect, fmt.Sprintf("0x%x", a))
		} else {
			res.OnlyA++
		}
	}
	for _, b := range B.Addrs {
		if !setA[b] {
			res.OnlyB++
		}
	}
	if len(res.Intersect) > 50 {
		res.Intersect = res.Intersect[:50]
	}
	// 同值交集(A与B在同一地址值相同)
	valMapB := map[uint64]string{}
	for i, a := range B.Addrs {
		if i < len(B.Values) {
			valMapB[a] = B.Values[i]
		}
	}
	for i, a := range A.Addrs {
		if setB[a] && i < len(A.Values) {
			if vb, ok := valMapB[a]; ok && vb == A.Values[i] {
				res.SameValue++
			}
		}
	}
	// 地址相邻检测(A与B之间的最小间隔<=gap)
	sorted := make([]uint64, 0, len(A.Addrs)+len(B.Addrs))
	for _, a := range A.Addrs {
		sorted = append(sorted, a)
	}
	for _, b := range B.Addrs {
		sorted = append(sorted, b)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	owner := map[uint64]string{}
	for _, a := range A.Addrs {
		owner[a] = "A"
	}
	for _, b := range B.Addrs {
		if owner[b] == "" {
			owner[b] = "B"
		} else {
			owner[b] = "AB"
		}
	}
	for i := 1; i < len(sorted) && len(res.Adjacent) < 50; i++ {
		d := sorted[i] - sorted[i-1]
		if d > 0 && d <= gap {
			oa, ob := owner[sorted[i-1]], owner[sorted[i]]
			if oa != ob && oa != "AB" && ob != "AB" { // A与B之间的相邻才记录
				res.Adjacent = append(res.Adjacent, AdjacentPair{
					A: fmt.Sprintf("0x%x(%s)", sorted[i-1], oa),
					B: fmt.Sprintf("0x%x(%s)", sorted[i], ob),
					Diff: d, ValA: "?", ValB: "?",
				})
			}
		}
	}
	// 区间分布备注
	binA := map[uint64]int{}
	for _, a := range A.Addrs {
		binA[a>>26]++
	}
	res.RangeNotes = append(res.RangeNotes, fmt.Sprintf("A集中在%d个64MB区间, B集中在%d个", len(binA), func() int {
		binB := map[uint64]int{}
		for _, b := range B.Addrs {
			binB[b>>26]++
		}
		return len(binB)
	}()))
	return res, nil
}

type AnalyzedValue struct {
	Value    string   `json:"value"`    // 渲染后的值
	Count    int      `json:"count"`    // 相同值的地址数
	Addrs    []string `json:"addrs"`    // 地址列表(最多10个)
	Pct      float64  `json:"pct"`      // 占比%
}

type AdjacentPair struct {
	A      string `json:"a"`      // 地址A
	B      string `json:"b"`      // 地址B
	Diff   uint64 `json:"diff"`   // 间隔字节
	ValA   string `json:"valA"`   // A当前值
	ValB   string `json:"valB"`   // B当前值
}

type AnalyzeResult struct {
	Total        int             `json:"total"`        // 分析地址总数
	Values       []AnalyzedValue `json:"values"`       // 按值分组统计
	Adjacent     []AdjacentPair  `json:"adjacent"`     // 地址相邻对(结构体特征)
	RangeCount   int             `json:"rangeCount"`   // 地址区间数
	RangeTop     []string        `json:"rangeTop"`     // 地址最集中的区间TOP10
	Fuzzy        bool            `json:"fuzzy"`        // 是否模糊搜索结果
	TruncatedTip string          `json:"truncatedTip"` // 结果被截断提示
}

// AnalyzeResults 分析当前搜索结果: 值分组统计 + 地址相邻检测(替代py脚本)
// maxScan: 最多分析多少个地址; gap: 相邻判定间隔字节
func (s *GGSession) AnalyzeResults(maxScan int, gap uint64) *AnalyzeResult {
	res := &AnalyzeResult{}
	if s.Search == nil {
		return res
	}
	var addrs []uintptr
	if s.Search.FuzzyInit {
		addrs = s.FuzzyResults(maxScan)
		res.Fuzzy = true
	} else {
		addrs = s.Search.Candidates
		if maxScan > 0 && len(addrs) > maxScan {
			addrs = addrs[:maxScan]
			res.TruncatedTip = fmt.Sprintf("仅分析前%d个地址(共%d个), 可增大maxScan", maxScan, len(s.Search.Candidates))
		}
	}
	res.Total = len(addrs)
	if res.Total == 0 {
		return res
	}
	t := s.Search.Type
	// 1. 值分组统计
	valMap := map[string]*AnalyzedValue{}
	valBuf := make([]byte, t.Size)
	for _, a := range addrs {
		if s.Mem.ReadAt(a, valBuf) != nil {
			continue
		}
		v := renderValue(valBuf, t)
		if vv, ok := valMap[v]; ok {
			vv.Count++
			if len(vv.Addrs) < 10 {
				vv.Addrs = append(vv.Addrs, fmt.Sprintf("0x%x", a))
			}
		} else {
			valMap[v] = &AnalyzedValue{Value: v, Count: 1, Addrs: []string{fmt.Sprintf("0x%x", a)}}
		}
	}
	for _, vv := range valMap {
		vv.Pct = float64(vv.Count) * 100 / float64(res.Total)
		res.Values = append(res.Values, *vv)
	}
	sort.Slice(res.Values, func(i, j int) bool { return res.Values[i].Count > res.Values[j].Count })
	if len(res.Values) > 20 {
		res.Values = res.Values[:20]
	}
	// 2. 地址相邻检测: 排序后找间隔<=gap的对
	sorted := make([]uintptr, len(addrs))
	copy(sorted, addrs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	maxPairs := 50
	for i := 1; i < len(sorted) && len(res.Adjacent) < maxPairs; i++ {
		d := uint64(sorted[i] - sorted[i-1])
		if d > 0 && d <= gap {
			va := make([]byte, t.Size)
			vb := make([]byte, t.Size)
			vaS, vbS := "?", "?"
			if s.Mem.ReadAt(sorted[i-1], va) == nil {
				vaS = renderValue(va, t)
			}
			if s.Mem.ReadAt(sorted[i], vb) == nil {
				vbS = renderValue(vb, t)
			}
			res.Adjacent = append(res.Adjacent, AdjacentPair{
				A: fmt.Sprintf("0x%x", sorted[i-1]), B: fmt.Sprintf("0x%x", sorted[i]),
				Diff: d, ValA: vaS, ValB: vbS,
			})
		}
	}
	// 3. 地址区间分布(64MB粒度)
	const binSize = 64 << 20
	binMap := map[uint64]int{}
	for _, a := range addrs {
		binMap[uint64(a)/binSize]++
	}
	res.RangeCount = len(binMap)
	type binT struct {
		key uint64
		n   int
	}
	bins := make([]binT, 0, len(binMap))
	for k, n := range binMap {
		bins = append(bins, binT{k, n})
	}
	sort.Slice(bins, func(i, j int) bool { return bins[i].n > bins[j].n })
	for i, b := range bins {
		if i >= 10 {
			break
		}
		res.RangeTop = append(res.RangeTop, fmt.Sprintf("0x%x-0x%x: %d个", b.key*binSize, (b.key+1)*binSize, b.n))
	}
	return res
}
