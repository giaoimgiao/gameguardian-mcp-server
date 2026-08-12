// ggmcp engine.go - 内核内存引擎: MemoryDriver supercall握手 + ioctl读写 + 搜索
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	// 内核驱动优先(抗检测), 块大小4KB
	if m.Kern != nil && m.Kern.ok {
		const chunk = 4096
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

func listProcesses() ([]ProcInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []ProcInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
		cmd = strings.TrimSpace(cmd)
		status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		var name, uid, rss string
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Name:") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "Uid:") {
				uid = strings.TrimSpace(strings.Fields(line)[1])
			}
			if strings.HasPrefix(line, "VmRSS:") {
				rss = strings.TrimSpace(strings.TrimPrefix(line, "VmRSS:"))
			}
		}
		if name == "" {
			name = cmd
		}
		out = append(out, ProcInfo{Pid: pid, Name: name, Cmdline: cmd, Uid: uid, Rss: rss})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pid < out[j].Pid })
	return out, nil
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
	return s.Path == "" && s.Offset == 0 && !strings.Contains(s.Prot, "x") && s.Start < 0x800000000000
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
}

type GGSession struct {
	mu      sync.Mutex
	Pid     int
	Kern    *KernelMem
	Mem     *MemIO
	Search  *SearchState
	Frozen  map[string]*FrozenEntry
}

type FrozenEntry struct {
	Addr  uintptr
	Type  MemType
	Value []byte
	Stop  chan struct{}
}

// 位图操作
func bmGet(bm []uint8, idx uint64) bool { return bm[idx/8]&(1<<(idx%8)) != 0 }
func bmSet(bm []uint8, idx uint64)       { bm[idx/8] |= 1 << (idx%8) }
func bmClear(bm []uint8, idx uint64)     { bm[idx/8] &^= 1 << (idx%8) }

// 对齐
func alignUp(a uintptr, n int) uintptr { return (a + uintptr(n) - 1) &^ uintptr(n-1) }
func alignDown(a uintptr, n int) uintptr { return a &^ uintptr(n-1) }

// ExactSearch 精确搜索
func (s *GGSession) ExactSearch(value []byte, t MemType, region string, rstart, rend uintptr, aligned bool) (int, error) {
	segs, err := readMaps(s.Pid)
	if err != nil {
		return 0, err
	}
	segs = selectSegments(segs, region, rstart, rend)
	align := 1
	if aligned {
		align = t.Size
	}
	var found []uintptr
	buf := make([]byte, 64*1024)
	for _, seg := range segs {
		// 起始对齐
		addr := seg.Start
		if aligned {
			addr = alignUp(addr, align)
		}
		for addr+uintptr(len(buf)) <= seg.End {
			if err := s.Mem.ReadAt(addr, buf); err != nil {
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
				if s.Mem.ReadAt(addr, rbuf) == nil {
					scanBuf(rbuf, value, t.Size, addr, aligned, &found)
				}
			}
		}
	}
	s.Search = &SearchState{
		Pid: s.Pid, Type: t, Aligned: aligned, Candidates: found,
		Segs: segs,
	}
	return len(found), nil
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
	// 尾部清零(只保留实际slot)
	for i := bits; i < bits*8; i++ {
		bm[i/8] &^= 1 << (i % 8)
	}
	// 读快照
	snaps := make([][]byte, len(segs))
	for i, seg := range segs {
		sz := int(seg.End - seg.Start)
		data := make([]byte, sz)
		if s.Mem.ReadAt(seg.Start, data) != nil {
			// 读失败段标记为空快照(该段候选会在refine时被剔除)
			data = nil
		}
		snaps[i] = data
	}
	s.Search = &SearchState{
		Pid: s.Pid, Type: t, Aligned: true, Bitmap: bm, Segs: segs,
		Snapshots: snaps, FuzzyInit: true,
	}
	return bits, nil
}

// FuzzyRefine 模糊细化: 与上一次快照比较, mode=increased/decreased/unchanged/changed
func (s *GGSession) FuzzyRefine(mode string) (uint64, error) {
	if s.Search == nil || !s.Search.FuzzyInit {
		return 0, errors.New("no fuzzy search initialized")
	}
	align := s.Search.Type.Size
	bm := s.Search.Bitmap
	keep := make([]uint8, len(bm))
	segCache := make([]byte, 64*1024)
	for si, seg := range s.Search.Segs {
		snap := s.Search.Snapshots[si]
		if snap == nil {
			continue
		}
		addr := seg.Start
		for addr < seg.End {
			n := uintptr(len(segCache))
			if addr+n > seg.End {
				n = seg.End - addr
			}
			if s.Mem.ReadAt(addr, segCache[:n]) != nil {
				break
			}
			// 遍历块内对齐slot
			start := uintptr(0)
			if addr == seg.Start {
				// 段首对齐: 段起点本身可能未按align对齐, slot从段起点开始
				start = 0
			}
			for off := start; off+uintptr(align) <= n; off += uintptr(align) {
				slotAddr := addr + off
				rel := slotAddr - seg.Start
				slotIdx := uint64(rel)/uint64(align) + segIdxBase(si, s.Search.Segs, align)
				if !(slotIdx < uint64(len(bm))*8 && bmGet(bm, slotIdx)) {
					continue
				}
				// 快照中的旧值(注意快照长度可能不足, 处理越界)
				if int(rel)+align > len(snap) {
					continue
				}
				old := snap[rel : rel+uintptr(align)]
				cur := segCache[off : off+uintptr(align)]
				if matchFuzzy(old, cur, mode) {
					bmSet(keep, slotIdx)
					// 更新快照为当前值(供下次比较)
					copy(old, cur)
				}
			}
			addr += n
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

func matchFuzzy(old, cur []byte, mode string) bool {
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
