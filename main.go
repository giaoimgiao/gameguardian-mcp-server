// ggmcp main.go - GG MCP 服务器: 把GG修改器功能暴露为MCP工具
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var session = &GGSession{Frozen: map[string]*FrozenEntry{}}

// ---------- MCP 协议 ----------
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

type toolResult struct {
	OK               bool                   `json:"ok"`
	Data             interface{}            `json:"data,omitempty"`
	Error            *toolError             `json:"error,omitempty"`
	NextActions      []interface{}          `json:"nextActions"`
	StructuredContent map[string]interface{} `json:"-"`
}

type toolError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Severity   string `json:"severity"`
	Recoverable bool  `json:"recoverable"`
}

func respond(w http.ResponseWriter, id interface{}, result interface{}, isErr bool) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id}
	if isErr {
		resp.Error = result
	} else {
		resp.Result = result
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// 工具定义
type toolDef struct {
	Name        string                 `json:"name"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Annotations map[string]interface{} `json:"annotations"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

func strSchema(desc string, required ...bool) map[string]interface{} {
	m := map[string]interface{}{"type": "string", "description": desc}
	if len(required) > 0 && required[0] {
		m["x-required"] = true
	}
	return m
}

func boolSchema(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "boolean", "description": desc}
}

func intSchema(desc string, extra ...bool) map[string]interface{} {
	return map[string]interface{}{"type": "integer", "description": desc}
}

func objectSchema(desc string, props map[string]interface{}, required []string) map[string]interface{} {
	return map[string]interface{}{
		"type":                 "object",
		"description":          desc,
		"properties":           props,
		"required":             required,
		"additionalProperties": false,
	}
}

var tools = []toolDef{
	{
		Name: "gg_status", Title: "会话状态", Description: "查看MCP会话状态: 当前附加进程、内存读写模式(内核/后备)、搜索结果数量。",
		InputSchema: objectSchema("无参数", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_list_processes", Title: "进程列表", Description: "列出所有进程(pid/名称/命令行/uid)。可选query按名称或包名过滤。",
		InputSchema: objectSchema("", map[string]interface{}{
			"query": strSchema("可选: 按进程名或包名过滤, 支持子串", false),
		}, []string{}),
	},
	{
		Name: "gg_attach", Title: "附加进程", Description: "附加目标进程(pid数字或包名/进程名), 后续所有内存操作针对该进程。自动初始化内核驱动通道。",
		InputSchema: objectSchema("", map[string]interface{}{
			"target": strSchema("目标: pid数字 或 包名/进程名(如 com.example.game)", true),
		}, []string{"target"}),
	},
	{
		Name: "gg_detach", Title: "分离进程", Description: "分离当前附加的进程, 清空搜索状态。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_target_info", Title: "目标信息", Description: "目标进程详情: 内存映射段数、模块列表(含基址)、搜索区域概况。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_module_list", Title: "模块列表", Description: "目标进程已加载模块(路径+基址+大小)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"query": strSchema("可选: 模块名过滤", false),
		}, []string{}),
	},
	{
		Name: "gg_search", Title: "精确搜索", Description: "已知值搜索。type: byte/word/dword/qword/float/double。region: all/heap/stack/anonymous/module 或自定义rangeStart-rangeEnd。",
		InputSchema: objectSchema("", map[string]interface{}{
			"value":      strSchema("搜索值, 如 100, 3.14, 0x1A2B, -5", true),
			"type":       strSchema("类型: byte|word|dword|qword|float|double", true),
			"region":     strSchema("区域: all|heap|stack|anonymous|module, 默认all", false),
			"rangeStart": strSchema("可选: 起始地址(0x...或十进制)", false),
			"rangeEnd":   strSchema("可选: 结束地址", false),
			"aligned":    boolSchema("按类型大小对齐(默认true)"),
		}, []string{"value", "type"}),
	},
	{
		Name: "gg_search_unknown_init", Title: "模糊搜索初始化", Description: "模糊搜索初始化(未知初值): 记录当前全部值作为快照, 候选为全地址。建议指定region缩小范围。",
		InputSchema: objectSchema("", map[string]interface{}{
			"type":       strSchema("类型: byte|word|dword|qword|float|double", true),
			"region":     strSchema("区域: all|heap|stack|anonymous|module", false),
			"rangeStart": strSchema("可选: 起始地址", false),
			"rangeEnd":   strSchema("可选: 结束地址", false),
		}, []string{"type"}),
	},
	{
		Name: "gg_search_refine", Title: "模糊搜索细化", Description: "模糊搜索细化: 与上一次快照比较。mode: increased(增大)/decreased(减小)/unchanged(不变)/changed(改变)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"mode": strSchema("increased|decreased|unchanged|changed", true),
		}, []string{"mode"}),
	},
	{
		Name: "gg_search_range", Title: "区间搜索", Description: "搜索值在[min,max]区间的地址。",
		InputSchema: objectSchema("", map[string]interface{}{
			"min":    strSchema("最小值", true),
			"max":    strSchema("最大值", true),
			"type":   strSchema("类型: byte|word|dword|qword|float|double", true),
			"region": strSchema("区域, 默认all", false),
		}, []string{"min", "max", "type"}),
	},
	{
		Name: "gg_result_count", Title: "结果数量", Description: "当前搜索结果数量。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_get_results", Title: "查看结果", Description: "查看搜索结果(地址+当前值)。limit默认50。",
		InputSchema: objectSchema("", map[string]interface{}{
			"limit":  intSchema("返回条数, 默认50, 最大1000"),
			"offset": intSchema("偏移, 默认0"),
		}, []string{}),
	},
	{
		Name: "gg_read", Title: "读内存", Description: "读取目标进程内存值。address支持0x十六进制或十进制。",
		InputSchema: objectSchema("", map[string]interface{}{
			"address": strSchema("地址, 如0x7f8a1234", true),
			"type":    strSchema("类型: byte|word|dword|qword|float|double", true),
		}, []string{"address", "type"}),
	},
	{
		Name: "gg_read_bytes", Title: "读原始字节", Description: "读取目标进程内存原始字节(hex)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"address": strSchema("地址", true),
			"size":    intSchema("字节数(1-4096)", true),
		}, []string{"address", "size"}),
	},
	{
		Name: "gg_hex_dump", Title: "Hex转储", Description: "Hex转储一段内存, 便于调试结构体。",
		InputSchema: objectSchema("", map[string]interface{}{
			"address": strSchema("起始地址", true),
			"size":    intSchema("字节数(1-256)", true),
		}, []string{"address", "size"}),
	},
	{
		Name: "gg_write", Title: "写内存", Description: "向目标进程指定地址写入值。",
		InputSchema: objectSchema("", map[string]interface{}{
			"address": strSchema("地址", true),
			"value":   strSchema("写入值, 如 9999, 3.5, 0xAB", true),
			"type":    strSchema("类型: byte|word|dword|qword|float|double", true),
		}, []string{"address", "value", "type"}),
	},
	{
		Name: "gg_set_results", Title: "批量修改结果", Description: "批量修改搜索结果的值。values: [{index或address, value, type可选}]。",
		InputSchema: objectSchema("", map[string]interface{}{
			"values": map[string]interface{}{"type": "array", "description": "[{index:0 或 address:'0x...', value:'9999', type:'dword'}]"},
			"type":   strSchema("默认类型(省略单项type时使用)", false),
		}, []string{"values"}),
	},
	{
		Name: "gg_clear_results", Title: "清空结果", Description: "清空搜索结果。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_freeze", Title: "冻结值", Description: "冻结指定地址的值(持续写入, 直到解冻)。index为搜索结果序号或address为地址。",
		InputSchema: objectSchema("", map[string]interface{}{
			"index":   intSchema("搜索结果序号(可选)"),
			"address": strSchema("地址(可选, 与index二选一)"),
			"value":   strSchema("冻结值, 默认当前值"),
			"type":    strSchema("类型, 默认搜索类型"),
			"id":      strSchema("冻结ID, 可选(默认自动生成)"),
		}, []string{}),
	},
	{
		Name: "gg_unfreeze", Title: "解冻", Description: "停止冻结。id指定冻结ID, 或all解冻全部。",
		InputSchema: objectSchema("", map[string]interface{}{
			"id": strSchema("冻结ID或'all'", true),
		}, []string{"id"}),
	},
	{
		Name: "gg_pause", Title: "暂停进程", Description: "暂停目标进程(断点模拟): SIGSTOP。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_resume", Title: "恢复进程", Description: "恢复目标进程: SIGCONT。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_module_base", Title: "模块基址", Description: "获取目标进程指定模块的基址。",
		InputSchema: objectSchema("", map[string]interface{}{
			"name": strSchema("模块名, 如 libil2cpp.so", true),
		}, []string{"name"}),
	},
	{
		Name: "gg_calc_offset", Title: "计算偏移", Description: "计算地址相对模块基址的偏移(用于定位静态偏移/找基址)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"address": strSchema("地址", true),
			"module":  strSchema("模块名(可选, 默认自动找包含该地址的模块)", false),
		}, []string{"address"}),
	},
	{
		Name: "gg_pointer_scan", Title: "指针扫描", Description: "扫描内存, 找值为targetAddress的指针(用于找指向游戏数据的指针链)。type: dword(32位指针)或qword(64位)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"targetAddress": strSchema("目标地址(要找指向它的指针)", true),
			"type":          strSchema("dword|qword, 默认qword", false),
			"region":        strSchema("扫描区域, 默认all", false),
		}, []string{"targetAddress"}),
	},
	{
		Name: "gg_shell", Title: "Shell命令", Description: "在目标进程上下文执行shell命令(危险操作, 谨慎)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"cmd": strSchema("shell命令", true),
		}, []string{"cmd"}),
	},
}

// ---------- 工具实现 ----------
func parseAddr(s string) (uintptr, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		return uintptr(v), err
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return uintptr(v), err
}

func requireTarget() error {
	if session.Pid == 0 {
		return fmt.Errorf("未附加进程, 先调用 gg_attach")
	}
	return nil
}

func handleTool(name string, args map[string]interface{}) (interface{}, error) {
	switch name {
	case "gg_status":
		modes := "未附加"
		if session.Pid != 0 {
			modes = "附加pid=" + strconv.Itoa(session.Pid)
			if session.Mem != nil {
				modes += " 读写模式=" + session.Mem.Mode
			}
		}
		cnt := 0
		if session.Search != nil {
			cnt = len(session.Search.Candidates)
		}
		return map[string]interface{}{
			"attached": session.Pid != 0,
			"pid":      session.Pid,
			"mode":     modes,
			"results":  cnt,
			"frozen":   len(session.Frozen),
		}, nil

	case "gg_list_processes":
		procs, err := listProcesses()
		if err != nil {
			return nil, err
		}
		query := strings.ToLower(getStr(args, "query"))
		var out []ProcInfo
		for _, p := range procs {
			if query != "" && !strings.Contains(strings.ToLower(p.Name), query) &&
				!strings.Contains(strings.ToLower(p.Cmdline), query) {
				continue
			}
			out = append(out, p)
		}
		if len(out) > 500 {
			out = out[:500]
		}
		return map[string]interface{}{"count": len(out), "processes": out}, nil

	case "gg_attach":
		target := getStr(args, "target")
		if target == "" {
			return nil, fmt.Errorf("target 不能为空")
		}
		var pid int
		if p, err := strconv.Atoi(target); err == nil {
			pid = p
		} else {
			procs, err := listProcesses()
			if err != nil {
				return nil, err
			}
			found := false
			for _, p := range procs {
				if p.Cmdline == target || p.Name == target ||
					strings.Contains(p.Cmdline, target) {
					pid = p.Pid
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("找不到进程: %s", target)
			}
		}
		// 验证进程存在
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			return nil, fmt.Errorf("进程不存在: %d", pid)
		}
		session.mu.Lock()
		session.Pid = pid
		session.Search = nil
		kern := &KernelMem{}
		if err := kern.Init(); err == nil {
			kern.mu.Lock()
			ok := kern.ok
			kern.mu.Unlock()
			if !ok {
				kern = nil
			}
		} else {
			kern = nil
		}
		session.Kern = kern
		session.Mem = &MemIO{Pid: pid, Kern: kern}
		session.mu.Unlock()
		mode := "kernel"
		if kern == nil {
			mode = "fallback(process_vm/mem)"
		}
		return map[string]interface{}{
			"attached": pid, "readMode": mode,
			"tip": "使用 gg_target_info 查看模块, gg_search 开始搜索",
		}, nil

	case "gg_detach":
		session.mu.Lock()
		session.Pid = 0
		session.Search = nil
		for _, f := range session.Frozen {
			close(f.Stop)
		}
		session.Frozen = map[string]*FrozenEntry{}
		session.mu.Unlock()
		return map[string]interface{}{"detached": true}, nil

	case "gg_target_info":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		segs, err := readMaps(session.Pid)
		if err != nil {
			return nil, err
		}
		var modules []map[string]interface{}
		seen := map[string]bool{}
		for _, s := range segs {
			if s.Path != "" && !seen[s.Path] {
				seen[s.Path] = true
				modules = append(modules, map[string]interface{}{
					"path": s.Path, "base": fmt.Sprintf("0x%x", s.Start),
					"size": fmt.Sprintf("0x%x", s.End-s.Start),
				})
			}
		}
		readable := 0
		var total uint64
		for _, s := range segs {
			if strings.Contains(s.Prot, "r") {
				readable++
				total += uint64(s.End - s.Start)
			}
		}
		return map[string]interface{}{
			"pid": session.Pid, "segments": len(segs), "readableSegs": readable,
			"readableTotal": fmt.Sprintf("%.1f MB", float64(total)/1048576),
			"modules":       modules,
		}, nil

	case "gg_module_list":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		segs, err := readMaps(session.Pid)
		if err != nil {
			return nil, err
		}
		query := strings.ToLower(getStr(args, "query"))
		var out []map[string]interface{}
		seen := map[string]bool{}
		for _, s := range segs {
			if s.Path == "" || seen[s.Path] {
				continue
			}
			if query != "" && !strings.Contains(strings.ToLower(s.Path), query) {
				continue
			}
			seen[s.Path] = true
			out = append(out, map[string]interface{}{
				"path": s.Path, "base": fmt.Sprintf("0x%x", s.Start),
				"size": fmt.Sprintf("0x%x", s.End-s.Start),
			})
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i]["path"].(string) < out[j]["path"].(string)
		})
		return map[string]interface{}{"count": len(out), "modules": out}, nil

	case "gg_search":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		t, err := typeByName(getStr(args, "type"))
		if err != nil {
			return nil, err
		}
		val, err := parseValue(getStr(args, "value"), t)
		if err != nil {
			return nil, fmt.Errorf("值解析失败: %v", err)
		}
		rs, re, err := getRange(args)
		if err != nil {
			return nil, err
		}
		aligned := true
		if v, ok := args["aligned"].(bool); ok {
			aligned = v
		}
		start := time.Now()
		n, err := session.ExactSearch(val, t, getStr(args, "region"), rs, re, aligned)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"found": n, "elapsedMs": time.Since(start).Milliseconds(),
			"type": t.Name, "tip": "用 gg_get_results 查看, gg_set_results 批量修改",
		}, nil

	case "gg_search_unknown_init":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		t, err := typeByName(getStr(args, "type"))
		if err != nil {
			return nil, err
		}
		rs, re, err := getRange(args)
		if err != nil {
			return nil, err
		}
		start := time.Now()
		n, err := session.FuzzyInit(t, getStr(args, "region"), rs, re)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"candidates": n, "elapsedMs": time.Since(start).Milliseconds(),
			"tip": "游戏内改变数值后调用 gg_search_refine",
		}, nil

	case "gg_search_refine":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		mode := getStr(args, "mode")
		switch mode {
		case "increased", "decreased", "unchanged", "changed":
		default:
			return nil, fmt.Errorf("mode 必须是 increased/decreased/unchanged/changed")
		}
		start := time.Now()
		n, err := session.FuzzyRefine(mode)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"candidates": n, "elapsedMs": time.Since(start).Milliseconds()}, nil

	case "gg_search_range":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		t, err := typeByName(getStr(args, "type"))
		if err != nil {
			return nil, err
		}
		minB, err := parseValue(getStr(args, "min"), t)
		if err != nil {
			return nil, err
		}
		maxB, err := parseValue(getStr(args, "max"), t)
		if err != nil {
			return nil, err
		}
		segs, err := readMaps(session.Pid)
		if err != nil {
			return nil, err
		}
		segs = selectSegments(segs, getStr(args, "region"), 0, 0)
		var found []uintptr
		buf := make([]byte, 64*1024)
		for _, seg := range segs {
			addr := alignUp(seg.Start, t.Size)
			for addr+uintptr(len(buf)) <= seg.End {
				if session.Mem.ReadAt(addr, buf) != nil {
					break
				}
				for i := 0; i+int(t.Size) <= len(buf); i += int(t.Size) {
					b := buf[i : i+int(t.Size)]
					if bytesRange(b, minB, maxB, t) {
						found = append(found, addr+uintptr(i))
					}
				}
				addr += uintptr(len(buf))
			}
		}
		session.Search = &SearchState{Pid: session.Pid, Type: t, Aligned: true, Candidates: found, Segs: segs}
		return map[string]interface{}{"found": len(found)}, nil

	case "gg_result_count":
		if session.Search == nil {
			return map[string]interface{}{"count": 0, "type": "none"}, nil
		}
		cnt := len(session.Search.Candidates)
		if session.Search.FuzzyInit {
			cnt = int(countBits(session.Search.Bitmap))
		}
		return map[string]interface{}{"count": cnt, "type": session.Search.Type.Name, "fuzzy": session.Search.FuzzyInit}, nil

	case "gg_get_results":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		if session.Search == nil {
			return map[string]interface{}{"results": []interface{}{}, "count": 0}, nil
		}
		limit := getInt(args, "limit", 50)
		offset := getInt(args, "offset", 0)
		if limit > 1000 {
			limit = 1000
		}
		t := session.Search.Type
		var addrs []uintptr
		if session.Search.FuzzyInit {
			addrs = session.FuzzyResults(offset + limit)
			if offset < len(addrs) {
				addrs = addrs[offset:]
			} else {
				addrs = nil
			}
		} else {
			cands := session.Search.Candidates
			if offset < len(cands) {
				addrs = cands[offset:]
			}
			if len(addrs) > limit {
				addrs = addrs[:limit]
			}
		}
		var out []map[string]interface{}
		for _, a := range addrs {
			buf := make([]byte, t.Size)
			var val string
			if session.Mem.ReadAt(a, buf) == nil {
				val = renderValue(buf, t)
			} else {
				val = "?"
			}
			out = append(out, map[string]interface{}{
				"address": fmt.Sprintf("0x%x", a), "value": val,
			})
		}
		total := len(session.Search.Candidates)
		if session.Search.FuzzyInit {
			total = int(countBits(session.Search.Bitmap))
		}
		return map[string]interface{}{"count": len(out), "total": total, "results": out}, nil

	case "gg_read":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		addr, err := parseAddr(getStr(args, "address"))
		if err != nil {
			return nil, err
		}
		t, err := typeByName(getStr(args, "type"))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, t.Size)
		if err := session.Mem.ReadAt(addr, buf); err != nil {
			return nil, fmt.Errorf("读取失败: %v", err)
		}
		return map[string]interface{}{
			"address": fmt.Sprintf("0x%x", addr), "type": t.Name,
			"value": renderValue(buf, t), "hex": renderHex(buf),
		}, nil

	case "gg_read_bytes":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		addr, err := parseAddr(getStr(args, "address"))
		if err != nil {
			return nil, err
		}
		size := getInt(args, "size", 16)
		if size < 1 || size > 4096 {
			return nil, fmt.Errorf("size 必须在1-4096")
		}
		buf := make([]byte, size)
		if err := session.Mem.ReadAt(addr, buf); err != nil {
			return nil, fmt.Errorf("读取失败: %v", err)
		}
		return map[string]interface{}{"address": fmt.Sprintf("0x%x", addr), "hex": renderHex(buf)}, nil

	case "gg_hex_dump":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		addr, err := parseAddr(getStr(args, "address"))
		if err != nil {
			return nil, err
		}
		size := getInt(args, "size", 64)
		if size < 1 || size > 256 {
			return nil, fmt.Errorf("size 必须在1-256")
		}
		buf := make([]byte, size)
		if err := session.Mem.ReadAt(addr, buf); err != nil {
			return nil, fmt.Errorf("读取失败: %v", err)
		}
		lines := []string{}
		for i := 0; i < len(buf); i += 16 {
			end := i + 16
			if end > len(buf) {
				end = len(buf)
			}
			hex := renderHex(buf[i:end])
			var ascii strings.Builder
			for _, b := range buf[i:end] {
				if b >= 32 && b < 127 {
					ascii.WriteByte(b)
				} else {
					ascii.WriteByte('.')
				}
			}
			lines = append(lines, fmt.Sprintf("%012x  %-32s  %s", addr+uintptr(i), hex, ascii.String()))
		}
		return map[string]interface{}{"address": fmt.Sprintf("0x%x", addr), "dump": lines}, nil

	case "gg_write":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		addr, err := parseAddr(getStr(args, "address"))
		if err != nil {
			return nil, err
		}
		t, err := typeByName(getStr(args, "type"))
		if err != nil {
			return nil, err
		}
		val, err := parseValue(getStr(args, "value"), t)
		if err != nil {
			return nil, err
		}
		if err := session.Mem.WriteAt(addr, val); err != nil {
			return nil, fmt.Errorf("写入失败: %v", err)
		}
		return map[string]interface{}{"address": fmt.Sprintf("0x%x", addr), "wrote": getStr(args, "value"), "type": t.Name}, nil

	case "gg_set_results":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		if session.Search == nil {
			return nil, fmt.Errorf("没有搜索结果")
		}
		vals, ok := args["values"].([]interface{})
		if !ok || len(vals) == 0 {
			return nil, fmt.Errorf("values 不能为空")
		}
		defType := getStr(args, "type")
		var written []map[string]interface{}
		for _, v := range vals {
			item, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			var addr uintptr
			if idx, ok := item["index"].(float64); ok {
				i := int(idx)
				if session.Search.FuzzyInit {
					all := session.FuzzyResults(i + 1)
					if i >= len(all) {
						continue
					}
					addr = all[i]
				} else {
					if i < 0 || i >= len(session.Search.Candidates) {
						continue
					}
					addr = session.Search.Candidates[i]
				}
			} else if as, ok := item["address"].(string); ok {
				a, err := parseAddr(as)
				if err != nil {
					continue
				}
				addr = a
			} else {
				continue
			}
			t := session.Search.Type
			ts := getStr(item, "type")
			if ts != "" {
				var err error
				t, err = typeByName(ts)
				if err != nil {
					continue
				}
			} else if defType != "" {
				var err error
				t, err = typeByName(defType)
				if err != nil {
					continue
				}
			}
			vs := getStr(item, "value")
			if vs == "" {
				continue
			}
			val, err := parseValue(vs, t)
			if err != nil {
				continue
			}
			if err := session.Mem.WriteAt(addr, val); err != nil {
				continue
			}
			written = append(written, map[string]interface{}{
				"address": fmt.Sprintf("0x%x", addr), "value": vs,
			})
		}
		return map[string]interface{}{"written": len(written), "items": written}, nil

	case "gg_clear_results":
		if session.Search != nil {
			session.Search.Candidates = nil
			session.Search.Bitmap = nil
			session.Search.Snapshots = nil
			session.Search.FuzzyInit = false
		}
		return map[string]interface{}{"cleared": true}, nil

	case "gg_freeze":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		var addr uintptr
		if idx, ok := args["index"].(float64); ok {
			if session.Search == nil {
				return nil, fmt.Errorf("没有搜索结果")
			}
			i := int(idx)
			if session.Search.FuzzyInit {
				all := session.FuzzyResults(i + 1)
				if i >= len(all) {
					return nil, fmt.Errorf("index越界")
				}
				addr = all[i]
			} else {
				if i < 0 || i >= len(session.Search.Candidates) {
					return nil, fmt.Errorf("index越界")
				}
				addr = session.Search.Candidates[i]
			}
		} else if as := getStr(args, "address"); as != "" {
			a, err := parseAddr(as)
			if err != nil {
				return nil, err
			}
			addr = a
		} else {
			return nil, fmt.Errorf("需要 index 或 address")
		}
		t := session.Search.Type
		if ts := getStr(args, "type"); ts != "" {
			var err error
			t, err = typeByName(ts)
			if err != nil {
				return nil, err
			}
		}
		val := make([]byte, t.Size)
		if vs := getStr(args, "value"); vs != "" {
			v, err := parseValue(vs, t)
			if err != nil {
				return nil, err
			}
			val = v
		} else {
			if err := session.Mem.ReadAt(addr, val); err != nil {
				return nil, fmt.Errorf("读取当前值失败: %v", err)
			}
		}
		id := getStr(args, "id")
		if id == "" {
			id = fmt.Sprintf("f%d", time.Now().UnixNano())
		}
		session.mu.Lock()
		if old, ok := session.Frozen[id]; ok {
			close(old.Stop)
		}
		stop := make(chan struct{})
		session.Frozen[id] = &FrozenEntry{Addr: addr, Type: t, Value: val, Stop: stop}
		session.mu.Unlock()
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					session.Mem.WriteAt(addr, val)
					time.Sleep(50 * time.Millisecond)
				}
			}
		}()
		return map[string]interface{}{"id": id, "address": fmt.Sprintf("0x%x", addr), "value": getStr(args, "value"), "frozen": true}, nil

	case "gg_unfreeze":
		id := getStr(args, "id")
		session.mu.Lock()
		if id == "all" {
			for _, f := range session.Frozen {
				close(f.Stop)
			}
			session.Frozen = map[string]*FrozenEntry{}
			session.mu.Unlock()
			return map[string]interface{}{"unfrozen": "all"}, nil
		}
		if f, ok := session.Frozen[id]; ok {
			close(f.Stop)
			delete(session.Frozen, id)
			session.mu.Unlock()
			return map[string]interface{}{"unfrozen": id}, nil
		}
		session.mu.Unlock()
		return nil, fmt.Errorf("冻结项不存在: %s", id)

	case "gg_pause":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		if err := syscall.Kill(session.Pid, syscall.SIGSTOP); err != nil {
			return nil, err
		}
		return map[string]interface{}{"paused": session.Pid}, nil

	case "gg_resume":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		if err := syscall.Kill(session.Pid, syscall.SIGCONT); err != nil {
			return nil, err
		}
		return map[string]interface{}{"resumed": session.Pid}, nil

	case "gg_module_base":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		segs, err := readMaps(session.Pid)
		if err != nil {
			return nil, err
		}
		base := moduleBase(segs, getStr(args, "name"))
		if base == 0 {
			return nil, fmt.Errorf("找不到模块: %s", getStr(args, "name"))
		}
		return map[string]interface{}{"module": getStr(args, "name"), "base": fmt.Sprintf("0x%x", base)}, nil

	case "gg_calc_offset":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		addr, err := parseAddr(getStr(args, "address"))
		if err != nil {
			return nil, err
		}
		segs, err := readMaps(session.Pid)
		if err != nil {
			return nil, err
		}
		mod := getStr(args, "module")
		var base uintptr
		if mod != "" {
			base = moduleBase(segs, mod)
		} else {
			for _, s := range segs {
				if s.Path != "" && addr >= s.Start && addr < s.End {
					mod = s.Path
					base = s.Start
					break
				}
			}
		}
		if base == 0 {
			return nil, fmt.Errorf("无法确定模块基址")
		}
		return map[string]interface{}{
			"module": mod, "moduleBase": fmt.Sprintf("0x%x", base),
			"address": fmt.Sprintf("0x%x", addr),
			"offset":  fmt.Sprintf("0x%x", addr-base),
		}, nil

	case "gg_pointer_scan":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		target, err := parseAddr(getStr(args, "targetAddress"))
		if err != nil {
			return nil, err
		}
		ts := getStr(args, "type")
		if ts == "" {
			ts = "qword"
		}
		t, err := typeByName(ts)
		if err != nil {
			return nil, err
		}
		if t.Code != 4 && t.Code != 8 {
			return nil, fmt.Errorf("指针扫描仅支持 dword/qword")
		}
		val, err := parseValue(fmt.Sprintf("0x%x", target), t)
		if err != nil {
			return nil, err
		}
		start := time.Now()
		n, err := session.ExactSearch(val, t, getStr(args, "region"), 0, 0, true)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"found": n, "target": fmt.Sprintf("0x%x", target),
			"elapsedMs": time.Since(start).Milliseconds(),
			"tip":       "用 gg_get_results 查看指针地址, 可继续 gg_calc_offset 算基址偏移",
		}, nil

	case "gg_shell":
		cmd := getStr(args, "cmd")
		if cmd == "" {
			return nil, fmt.Errorf("cmd 不能为空")
		}
		out, err := runShell(cmd)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"output": out}, nil
	}
	return nil, fmt.Errorf("未知工具: %s", name)
}

func getStr(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]interface{}, k string, def int) int {
	if v, ok := m[k].(float64); ok {
		return int(v)
	}
	return def
}

func getRange(args map[string]interface{}) (uintptr, uintptr, error) {
	var rs, re uintptr
	if s := getStr(args, "rangeStart"); s != "" {
		a, err := parseAddr(s)
		if err != nil {
			return 0, 0, err
		}
		rs = a
	}
	if s := getStr(args, "rangeEnd"); s != "" {
		a, err := parseAddr(s)
		if err != nil {
			return 0, 0, err
		}
		re = a
	}
	return rs, re, nil
}

func bytesRange(b, min, max []byte, t MemType) bool {
	return bytesCompare(b, min) >= 0 && bytesCompare(b, max) <= 0
}

func bytesCompare(a, b []byte) int {
	av, bv := binaryLE(a), binaryLE(b)
	if av < bv {
		return -1
	}
	if av > bv {
		return 1
	}
	return 0
}

func binaryLE(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func runShell(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

// ---------- HTTP MCP 入口 ----------
func main() {
	addr := ":8788"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	http.HandleFunc("/mcp", mcpHandler)
	fmt.Printf("GG MCP server listening on %s/mcp\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func mcpHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", 400)
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	id := req.ID
	switch req.Method {
	case "initialize":
		respond(w, id, map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"serverInfo":      map[string]interface{}{"name": "GG MCP", "version": "1.0.0"},
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{
					"availableTools": map[string]interface{}{},
				},
			},
		}, false)
	case "tools/list":
		respond(w, id, map[string]interface{}{"tools": tools}, false)
	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		json.Unmarshal(req.Params, &params)
		result, err := handleTool(params.Name, params.Arguments)
		tr := toolResult{OK: err == nil, NextActions: []interface{}{}}
		if err != nil {
			tr.OK = false
			tr.Error = &toolError{Code: "TOOL_ERROR", Message: err.Error(), Severity: "fatal", Recoverable: true}
		} else {
			tr.Data = result
		}
		// 转成MCP content格式
		dataJSON, _ := json.Marshal(tr)
		content := []map[string]interface{}{
			{"type": "text", "text": string(dataJSON)},
		}
		sc := map[string]interface{}{
			"ok": tr.OK, "data": tr.Data, "error": tr.Error, "nextActions": tr.NextActions,
		}
		respond(w, id, map[string]interface{}{
			"content":          content,
			"structuredContent": sc,
			"isError":          !tr.OK,
		}, false)
	case "notifications/initialized", "initialized":
		// 无响应
		w.WriteHeader(202)
	default:
		respond(w, id, map[string]interface{}{"error": "unknown method: " + req.Method}, true)
	}
}