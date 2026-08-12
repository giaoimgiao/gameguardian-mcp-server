// ggmcp main.go - GG MCP 服务器: 把GG修改器功能暴露为MCP工具
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
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
func arrSchema(desc string, required ...bool) map[string]interface{} {
	m := map[string]interface{}{"type": "array", "description": desc, "items": map[string]interface{}{"type": "string"}}
	if len(required) > 0 && required[0] {
		m["x-required"] = true
	}
	return m
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
		Name: "gg_list_processes", Title: "进程列表", Description: "列出进程(pid/名称/命令行/uid)。可配置: query过滤, includeKernel(是否含内核线程,默认false), appOnly(仅应用进程), sort(active/pid/adj/name), limit+offset分页扩展。",
		InputSchema: objectSchema("", map[string]interface{}{
			"query":         strSchema("可选: 按进程名或包名过滤, 支持子串", false),
			"includeKernel": boolSchema("是否包含内核线程, 默认false"),
			"appOnly":       boolSchema("true=仅显示应用进程(uid>=10000)"),
			"sort":          strSchema("排序: active(应用优先+活跃度,默认)|pid|adj(活跃度)|name", false),
			"limit":         intSchema("返回条数, 默认100, 最大1000(超出用offset翻页)"),
			"offset":        intSchema("偏移, 默认0(配合limit分页扩展)"),
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
		Name: "gg_search", Title: "精确搜索", Description: "已知值搜索。type: auto(自动: byte/word/dword/qword/float全扫,多线程最快)|byte|word|dword|qword|float|double。region: all/heap/stack/anonymous/module 或自定义rangeStart-rangeEnd。**两步搜索**: 先搜当前值→游戏内让值变化→再调本工具并设refine=true(仅在现有结果中过滤,秒级), 命中大幅缩小。",
		InputSchema: objectSchema("", map[string]interface{}{
			"value":      strSchema("搜索值, 如 100, 3.14, 0x1A2B, -5", true),
			"type":       strSchema("类型: auto|byte|word|dword|qword|float|double", true),
			"region":     strSchema("区域: all|heap|stack|anonymous|module, 默认all", false),
			"rangeStart": strSchema("可选: 起始地址(0x...或十进制)", false),
			"rangeEnd":   strSchema("可选: 结束地址", false),
			"aligned":    boolSchema("按类型大小对齐(默认true)"),
			"refine":     boolSchema("两步搜索: 只在现有结果中过滤值为value的地址(需先做过一次搜索)"),
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
		Name: "gg_search_refine", Title: "模糊搜索细化", Description: "模糊搜索细化: 与上一次快照比较。mode: increased(增大)/decreased(减小)/unchanged(不变)/changed(改变)/range(值范围过滤, 配minValue/maxValue)。range模式适合过滤坐标: 坐标值必在地图尺寸内, 垃圾值不在。",
		InputSchema: objectSchema("", map[string]interface{}{
			"mode":        strSchema("increased|decreased|unchanged|changed|range", true),
			"minValue":    intSchema("range模式: 最小浮点值"),
			"maxValue":    intSchema("range模式: 最大浮点值"),
			"minAbsValue": intSchema("range模式: 最小绝对值(剔除1e-17级垃圾值)"),
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
		Name: "gg_watch", Title: "持续监控地址", Description: "持续监控一组地址的值变化(坐标流/动态值检测)。采样期间值变化会按时间记录, 返回每地址变化次数/起止值/动态判定。适合监控NPC坐标、玩家属性等持续变化的值。",
		InputSchema: objectSchema("", map[string]interface{}{
			"addresses":   arrSchema("地址数组, 如[\"0x8ACBB74C\",\"0x8ACBB750\"]", true),
			"type":        strSchema("类型: byte|word|dword|qword|float|double", true),
			"durationMs":  intSchema("监控时长ms(默认3000)"),
			"intervalMs":  intSchema("采样间隔ms(默认100, 最小10)"),
			"onlyChanges": boolSchema("只记录变化(默认true)"),
		}, []string{"addresses", "type"}),
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
		Name: "gg_set_results", Title: "批量修改结果", Description: "批量修改搜索结果的值。两种模式: ①values: [{index或address, value, type可选}] ②all:true + value + type(可选): 一键把全部结果改成同一值(两步搜索锁定后推荐)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"values": map[string]interface{}{"type": "array", "description": "[{index:0 或 address:'0x...', value:'9999', type:'dword'}]"},
			"type":   strSchema("默认类型(省略单项type时使用)", false),
			"all":    boolSchema("true=一键修改全部结果(需配合value)"),
			"value":  strSchema("all=true时必填: 所有结果改为该值", false),
		}, []string{}),
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
		Name: "gg_freeze_results", Title: "批量冻结结果集", Description: "把当前搜索结果(全部或过滤后)批量冻结为同一值——解决'1560个候选逐地址冻结'的痛点。支持值范围过滤(excludeNaN/minValue/maxValue/minAbsValue)和pairOnly(只冻结相邻8字节成对的X/Z坐标对)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"value":        strSchema("冻结值(必填)", true),
			"type":         strSchema("类型,默认搜索类型"),
			"minValue":     map[string]interface{}{"type": "number", "description": "可选:只冻结当前值>=此值的候选"},
			"maxValue":     map[string]interface{}{"type": "number", "description": "可选:只冻结当前值<=此值的候选"},
			"minAbsValue":  map[string]interface{}{"type": "number", "description": "可选:只冻结|当前值|>=此值的候选"},
			"excludeNaN":   boolSchema("可选:剔除NaN候选,默认true"),
			"pairOnly":     boolSchema("可选:只冻结'成对地址'(addr与addr+8都在候选集)——用于锁定坐标X/Z对,避免误冻动画/计时器噪声"),
			"maxCount":     intSchema("可选:最多冻结个数,默认2000(防呆,防止一次冻结过多导致游戏崩溃)"),
		}, []string{"value"}),
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
	{
		Name: "gg_config_get", Title: "查看配置", Description: "查看服务器运行时配置(搜索上限/快照上限/冻结间隔/分页默认值等)。所有值均可通过gg_config_set动态调整并持久化。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_config_set", Title: "修改配置", Description: "动态修改服务器配置并持久化到config.json(立即生效)。支持: searchMaxResults(精确搜索最大结果数,0=无限), fuzzyMaxSnapshotMB(模糊快照上限MB), freezeIntervalMs(冻结写入间隔ms), listDefaultLimit/listMaxLimit(进程列表分页), resultsDefaultLimit/resultsMaxLimit(结果查看分页), setAllMax(一键全改最大数)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"searchMaxResults":    intSchema("返回显示最大结果数(0=无限制, 不影响候选收集)"),
			"searchCandidateMax":  intSchema("候选全量上限(内存保护, 0=无限; 默认500万)"),
			"fuzzyMaxSnapshotMB":  intSchema("模糊搜索快照上限MB(最小16)"),
			"freezeIntervalMs":    intSchema("冻结写入间隔ms(最小5)"),
			"listDefaultLimit":    intSchema("进程列表默认条数"),
			"listMaxLimit":        intSchema("进程列表最大条数"),
			"resultsDefaultLimit": intSchema("结果查看默认条数"),
			"resultsMaxLimit":     intSchema("结果查看最大条数"),
			"setAllMax":           intSchema("一键全改最大地址数"),
		}, []string{}),
	},
	{
		Name: "gg_search_xor", Title: "Xor加密值搜索", Description: "加密值搜索(游戏内存值=明文XOR密钥)。第1步: 搜明文值, 自动统计密钥K分布(众数K=最可能的加密密钥), 并把K=众数的地址设为候选。第2步: 游戏内变值后再次调用并设refine=true, 保留K不变的地址=真身。region/rangeStart/rangeEnd同上。",
		InputSchema: objectSchema("", map[string]interface{}{
			"value":      strSchema("明文搜索值, 如 4, 100", true),
			"type":       strSchema("类型: dword|qword(Xor仅支持4/8字节)", true),
			"region":     strSchema("区域: all|heap|stack|anonymous|module, 默认all", false),
			"rangeStart": strSchema("可选: 起始地址", false),
			"rangeEnd":   strSchema("可选: 结束地址", false),
			"refine":     boolSchema("第2步: 在现有候选中保留密钥K不变的地址"),
		}, []string{"value", "type"}),
	},
	{
		Name: "gg_snapshot_results", Title: "保存结果快照", Description: "将当前搜索结果保存为命名快照(持久化到磁盘, 跨重启可用)。之后可与其他结果做交叉分析(gg_cross_analyze)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"id":     strSchema("快照名(可选, 默认自动生成)", false),
			"source": strSchema("来源描述(如'攻击力搜索12780')", false),
		}, []string{}),
	},
	{
		Name: "gg_list_snapshots", Title: "列出快照", Description: "列出所有已保存的结果快照(id/进程/类型/数量/来源/时间)。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
	},
	{
		Name: "gg_delete_snapshot", Title: "删除快照", Description: "删除指定快照(id='all'删除全部)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"id": strSchema("快照名或'all'", true),
		}, []string{"id"}),
	},
	{
		Name: "gg_cross_analyze", Title: "交叉分析", Description: "交叉分析两个结果集(替代外部脚本): 交集地址/仅A/仅B/地址相邻对(结构体特征)/同值交集。snapA/snapB为快照名, 传'current'表示当前搜索结果。gap: 相邻判定间隔字节(默认16)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"snapA": strSchema("快照名 或 'current'(当前搜索结果)", true),
			"snapB": strSchema("快照名 或 'current'", true),
			"gap":   intSchema("地址相邻判定间隔字节, 默认16"),
		}, []string{"snapA", "snapB"}),
	},
	{
		Name: "gg_analyze_results", Title: "分析结果", Description: "分析当前搜索结果(替代外部脚本): 值分组统计+地址相邻检测(结构体特征)+地址区间分布。maxScan最多分析地址数(默认全部), gap相邻判定间隔字节(默认16)。",
		InputSchema: objectSchema("", map[string]interface{}{
			"maxScan": intSchema("最多分析地址数, 0=全部(默认)"),
			"gap":     intSchema("地址相邻判定间隔字节, 默认16"),
		}, []string{}),
	},
	{
		Name: "gg_export_results", Title: "导出结果", Description: "导出当前搜索结果到文件(JSON格式), 返回文件路径和大小。便于持久化分析。",
		InputSchema: objectSchema("", map[string]interface{}{
			"path": strSchema("导出路径, 默认/data/local/tmp/ggmcp/results_<时间戳>.json", false),
		}, []string{}),
	},
	{
		Name: "gg_server_stop", Title: "关闭服务器", Description: "停止ggmcp服务器进程(用完即关: 释放内存、减少驻留痕迹)。再次使用需通过shell执行 /data/local/tmp/ggmcp_ctl.sh start 或重启手机(开机自启)。",
		InputSchema: objectSchema("", map[string]interface{}{}, []string{}),
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
		includeKernel, _ := args["includeKernel"].(bool)
		appOnly, _ := args["appOnly"].(bool)
		sortMode := getStr(args, "sort")
		if sortMode == "" {
			sortMode = "active"
		}
		procs, err := listProcesses(includeKernel, appOnly, sortMode)
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
		// 分页: limit默认取配置(可gg_config_set), offset翻页扩展
		limit := getInt(args, "limit", cfg.ListDefaultLimit)
		if limit <= 0 {
			limit = cfg.ListDefaultLimit
		}
		if limit > cfg.ListMaxLimit {
			limit = cfg.ListMaxLimit
		}
		offset := getInt(args, "offset", 0)
		if offset < 0 {
			offset = 0
		}
		total := len(out)
		start := offset
		if start > total {
			start = total
		}
		end := start + limit
		if end > total {
			end = total
		}
		return map[string]interface{}{
			"total":     total,
			"returned":  end - start,
			"limit":     limit,
			"offset":    offset,
			"hasMore":   end < total,
			"filters":   map[string]interface{}{"includeKernel": includeKernel, "appOnly": appOnly, "sort": sortMode},
			"processes": out[start:end],
		}, nil

	case "gg_attach":
		target := getStr(args, "target")
		if target == "" {
			return nil, fmt.Errorf("target 不能为空")
		}
		var pid int
		if p, err := strconv.Atoi(target); err == nil {
			pid = p
		} else {
			// 按名称找pid: 全量枚举(含内核+应用, 按pid排序, 保证能找到)
			procs, err := listProcesses(true, false, "pid")
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
		targets := make([]*FrozenEntry, 0, len(session.Frozen))
		for _, f := range session.Frozen {
			targets = append(targets, f)
		}
		session.Frozen = map[string]*FrozenEntry{}
		session.mu.Unlock()
		for _, f := range targets {
			f.StopFreeze()
			f.WaitDone(3 * time.Second)
		}
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
		typeName := getStr(args, "type")
		// Auto自动类型搜索(byte/word/dword/qword/float全覆盖, 多线程并行)
		if typeName == "auto" {
			v, err := strconv.Atoi(strings.TrimSpace(getStr(args, "value")))
			if err != nil {
				return nil, fmt.Errorf("auto搜索value必须是整数: %v", err)
			}
			rs, re, err := getRange(args)
			if err != nil {
				return nil, err
			}
			start := time.Now()
			res, err := session.AutoSearch(v, getStr(args, "region"), rs, re)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"auto": res, "elapsedMs": time.Since(start).Milliseconds(),
				"tip": "多类型自动搜索完成, 用 gg_get_results 查看; 游戏内变值后 refine=true 锁定",
			}, nil
		}
		t, err := typeByName(typeName)
		if err != nil {
			return nil, err
		}
		val, err := parseValue(getStr(args, "value"), t)
		if err != nil {
			return nil, fmt.Errorf("值解析失败: %v", err)
		}
		// 两步搜索: refine=true 时在现有结果中过滤
		if refine, _ := args["refine"].(bool); refine {
			if session.Search == nil || session.Search.FuzzyInit {
				return nil, fmt.Errorf("refine需要先做一次精确搜索(gg_search), 且不能是模糊搜索")
			}
			start := time.Now()
			n, err := session.Refine(val, t)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"found": n, "elapsedMs": time.Since(start).Milliseconds(),
				"refined": true, "type": t.Name,
				"tip": "结果已缩小, 用 gg_get_results 查看, gg_set_results 修改; 若仍多可继续游戏内变值再refine",
			}, nil
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
		n, truncated, err := session.ExactSearch(val, t, getStr(args, "region"), rs, re, aligned)
		if err != nil {
			return nil, err
		}
		resp := map[string]interface{}{
			"found": n, "elapsedMs": time.Since(start).Milliseconds(),
			"type": t.Name, "tip": "用 gg_get_results 查看, gg_set_results 批量修改; 建议游戏内变值后用 refine=true 两步搜索锁定真身",
		}
		if truncated {
			resp["truncated"] = true
			resp["tip"] = "候选超searchCandidateMax已截断, 可用gg_config_set调大; 用 gg_get_results 查看"
		}
		return resp, nil

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
		tip := "游戏内改变数值后调用 gg_search_refine"
		if session.Truncated {
			tip = fmt.Sprintf("快照超过%dMB上限被截断(仅覆盖前%dMB), 建议用region或rangeStart/rangeEnd缩小范围, 或gg_config_set调大fuzzyMaxSnapshotMB", cfg.FuzzyMaxSnapshotMB, cfg.FuzzyMaxSnapshotMB)
		}
		return map[string]interface{}{
			"candidates": n, "elapsedMs": time.Since(start).Milliseconds(),
			"tip": tip,
		}, nil

	case "gg_search_refine":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		mode := getStr(args, "mode")
		var minV, maxV *float64
		if mv, ok := args["minValue"].(float64); ok {
			minV = &mv
		}
		if mv, ok := args["maxValue"].(float64); ok {
			maxV = &mv
		}
		var minAbs *float64
		if mv, ok := args["minAbsValue"].(float64); ok {
			minAbs = &mv
		}
		switch mode {
		case "increased", "decreased", "unchanged", "changed", "range":
		default:
			return nil, fmt.Errorf("mode 必须是 increased/decreased/unchanged/changed/range")
		}
		if mode == "range" && minV == nil && maxV == nil {
			return nil, fmt.Errorf("range模式需要minValue或maxValue")
		}
		start := time.Now()
		n, err := session.FuzzyRefine(mode, minV, maxV, minAbs)
		if err != nil {
			return nil, err
		}
		resp := map[string]interface{}{"candidates": n, "elapsedMs": time.Since(start).Milliseconds(), "mode": mode}
		if mode == "range" {
			resp["tip"] = "值范围过滤: 保留当前值在[minValue,maxValue]内的候选(坐标过滤利器)"
		}
		return resp, nil

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
		limit := getInt(args, "limit", cfg.ResultsDefaultLimit)
		offset := getInt(args, "offset", 0)
		if limit > cfg.ResultsMaxLimit {
			limit = cfg.ResultsMaxLimit
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

	case "gg_watch":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		rawAddrs, ok := args["addresses"].([]interface{})
		if !ok || len(rawAddrs) == 0 {
			return nil, fmt.Errorf("addresses 必须是地址数组, 如[\"0x8ACBB74C\"]")
		}
		var addrs []uintptr
		for _, ra := range rawAddrs {
			as, ok := ra.(string)
			if !ok {
				return nil, fmt.Errorf("地址必须是字符串: %v", ra)
			}
			a, err := parseAddr(as)
			if err != nil {
				return nil, fmt.Errorf("地址解析失败 %s: %v", as, err)
			}
			addrs = append(addrs, a)
		}
		t, err := typeByName(getStr(args, "type"))
		if err != nil {
			return nil, err
		}
		duration := getInt(args, "durationMs", 3000)
		interval := getInt(args, "intervalMs", 100)
		onlyChanges := true
		if v, ok := args["onlyChanges"].(bool); ok {
			onlyChanges = v
		}
		start := time.Now()
		res, err := session.WatchAddrs(addrs, t, int64(duration), int64(interval), onlyChanges)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"watch": res, "elapsedMs": time.Since(start).Milliseconds(),
			"tip": "active=true的地址在持续变化(动态值, 如坐标); 配合gg_freeze可锁值, 配合gg_hex_dump看结构",
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
		// 一键修改全部结果: all=true + value + type
		if all, _ := args["all"].(bool); all {
			vs := getStr(args, "value")
			if vs == "" {
				return nil, fmt.Errorf("all=true 时需要 value 参数")
			}
			t := session.Search.Type
			if ts := getStr(args, "type"); ts != "" {
				var err error
				t, err = typeByName(ts)
				if err != nil {
					return nil, err
				}
			}
			val, err := parseValue(vs, t)
			if err != nil {
				return nil, fmt.Errorf("值解析失败: %v", err)
			}
			var addrs []uintptr
			if session.Search.FuzzyInit {
				addrs = session.FuzzyResults(cfg.SetAllMax)
			} else {
				addrs = session.Search.Candidates
			}
			// 上限保护(可gg_config_set调整)
			if len(addrs) > cfg.SetAllMax {
				addrs = addrs[:cfg.SetAllMax]
			}
			written := 0
			var failed int
			for _, a := range addrs {
				if session.Mem.WriteAt(a, val) == nil {
					written++
				} else {
					failed++
				}
			}
			return map[string]interface{}{
				"all": true, "written": written, "failed": failed, "total": len(addrs),
			}, nil
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
		var t MemType
		if ts := getStr(args, "type"); ts != "" {
			var err error
			t, err = typeByName(ts)
			if err != nil {
				return nil, err
			}
		} else if session.Search != nil {
			t = session.Search.Type
		} else {
			return nil, fmt.Errorf("未执行过搜索, 请显式指定type(如dword)")
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
			old.StopFreeze() // 替换前先安全停旧的
			old.WaitDone(2 * time.Second)
		}
		stop := make(chan struct{})
		done := make(chan struct{})
		session.Frozen[id] = &FrozenEntry{Addr: addr, Type: t, Value: val, Stop: stop, Done: done}
		session.mu.Unlock()
		go func() {
			defer close(done) // 退出时通知, 解冻可确认
			interval := time.Duration(cfg.FreezeIntervalMs) * time.Millisecond
			for {
				select {
				case <-stop:
					return
				case <-time.After(interval):
					session.Mem.WriteAt(addr, val)
				}
			}
		}()
		return map[string]interface{}{"id": id, "address": fmt.Sprintf("0x%x", addr), "value": getStr(args, "value"), "frozen": true}, nil

	case "gg_unfreeze":
		id := getStr(args, "id")
		session.mu.Lock()
		var targets []*FrozenEntry
		if id == "all" {
			for _, f := range session.Frozen {
				targets = append(targets, f)
			}
		} else if f, ok := session.Frozen[id]; ok {
			targets = append(targets, f)
		} else {
			session.mu.Unlock()
			return nil, fmt.Errorf("冻结项不存在: %s", id)
		}
		// 先全部发出停止信号, 再等待退出确认(避免持锁等待)
		for _, f := range targets {
			f.StopFreeze()
		}
		session.mu.Unlock()
		// 等待goroutine真正退出, 超时视为解冻失败
		timeout := 3 * time.Second
		for _, f := range targets {
			if !f.WaitDone(timeout) {
				return nil, fmt.Errorf("解冻超时: goroutine未退出, 请重试或gg_server_stop")
			}
		}
		session.mu.Lock()
		if id == "all" {
			session.Frozen = map[string]*FrozenEntry{}
		} else {
			delete(session.Frozen, id)
		}
		session.mu.Unlock()
		return map[string]interface{}{"unfrozen": id, "confirmed": true}, nil

	case "gg_freeze_results":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		if session.Search == nil {
			return nil, fmt.Errorf("没有搜索结果,请先搜索")
		}
		vs := getStr(args, "value")
		if vs == "" {
			return nil, fmt.Errorf("value必填(批量冻结值)")
		}
		var t MemType
		if ts := getStr(args, "type"); ts != "" {
			var err error
			t, err = typeByName(ts)
			if err != nil {
				return nil, err
			}
		} else {
			t = session.Search.Type
		}
		val, err := parseValue(vs, t)
		if err != nil {
			return nil, err
		}
		// 过滤参数
		var minV, maxV, minAbs *float64
		if f, ok := args["minValue"].(float64); ok {
			minV = &f
		}
		if f, ok := args["maxValue"].(float64); ok {
			maxV = &f
		}
		if f, ok := args["minAbsValue"].(float64); ok {
			minAbs = &f
		}
		excludeNaN := true
		if b, ok := args["excludeNaN"].(bool); ok {
			excludeNaN = b
		}
		pairOnly := false
		if b, ok := args["pairOnly"].(bool); ok {
			pairOnly = b
		}
		maxCount := 2000
		if f, ok := args["maxCount"].(float64); ok {
			maxCount = int(f)
		}
		if maxCount <= 0 || maxCount > 100000 {
			maxCount = 2000
		}
		// 收集全部候选
		var all []uintptr
		if session.Search.FuzzyInit {
			all = session.FuzzyResults(100000000)
		} else {
			all = session.Search.Candidates
		}
		if len(all) > maxCount {
			all = all[:maxCount]
		}
		// pairOnly: addr与addr+8都要在候选集(坐标X/Z对)
		var pairSet map[uintptr]bool
		if pairOnly {
			pairSet = make(map[uintptr]bool, len(all))
			for _, a := range all {
				pairSet[a] = true
			}
		}
		// 值过滤
		buf := make([]byte, 8)
		var kept []uintptr
		for _, a := range all {
			if pairOnly && !pairSet[a+8] {
				continue
			}
			if minV != nil || maxV != nil || minAbs != nil || excludeNaN {
				if err := session.Mem.ReadAt(a, buf[:t.Size]); err != nil {
					continue
				}
				v := bytesToFloatVal(buf[:t.Size])
				if excludeNaN && v != v {
					continue
				}
				if minV != nil && v < *minV {
					continue
				}
				if maxV != nil && v > *maxV {
					continue
				}
				if minAbs != nil && math.Abs(v) < *minAbs {
					continue
				}
			}
			kept = append(kept, a)
		}
		// 批量冻结
		frozen := 0
		now := time.Now().UnixNano()
		for i, a := range kept {
			id := fmt.Sprintf("fr%d_%d", now, i)
			stop := make(chan struct{})
			done := make(chan struct{})
			session.mu.Lock()
			if old, ok := session.Frozen[id]; ok {
				old.StopFreeze()
				old.WaitDone(2 * time.Second)
			}
			session.Frozen[id] = &FrozenEntry{Addr: a, Type: t, Value: val, Stop: stop, Done: done}
			session.mu.Unlock()
			go func(addr uintptr) {
				defer close(done)
				interval := time.Duration(cfg.FreezeIntervalMs) * time.Millisecond
				for {
					select {
					case <-stop:
						return
					case <-time.After(interval):
						session.Mem.WriteAt(addr, val)
					}
				}
			}(a)
			frozen++
		}
		return map[string]interface{}{
			"total":  len(all),
			"kept":   len(kept),
			"frozen": frozen,
			"value":  vs,
			"type":   t.Name,
			"hint":   "用gg_unfreeze id=all解冻全部",
		}, nil
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
		n, truncated, err := session.ExactSearch(val, t, getStr(args, "region"), 0, 0, true)
		if err != nil {
			return nil, err
		}
		resp := map[string]interface{}{
			"found": n, "target": fmt.Sprintf("0x%x", target),
			"elapsedMs": time.Since(start).Milliseconds(),
			"tip":       "用 gg_get_results 查看指针地址, 可继续 gg_calc_offset 算基址偏移",
		}
		if truncated {
			resp["truncated"] = true
		}
		return resp, nil

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

	case "gg_config_get":
		return map[string]interface{}{
			"config":             cfg,
			"configPath":         ConfigPath,
			"tip":                "用 gg_config_set 修改任意项(立即生效+持久化)",
		}, nil

	case "gg_config_set":
		type kv struct {
			k string
			v *int
		}
		items := []kv{
			{"searchMaxResults", &cfg.SearchMaxResults},
			{"searchCandidateMax", &cfg.SearchCandidateMax},
			{"fuzzyMaxSnapshotMB", &cfg.FuzzyMaxSnapshotMB},
			{"freezeIntervalMs", &cfg.FreezeIntervalMs},
			{"listDefaultLimit", &cfg.ListDefaultLimit},
			{"listMaxLimit", &cfg.ListMaxLimit},
			{"resultsDefaultLimit", &cfg.ResultsDefaultLimit},
			{"resultsMaxLimit", &cfg.ResultsMaxLimit},
			{"setAllMax", &cfg.SetAllMax},
		}
		var changed []string
		for _, it := range items {
			if v, ok := args[it.k].(float64); ok {
				*it.v = int(v)
				changed = append(changed, it.k)
			}
		}
		// 合法性校验(与LoadConfig一致)
		if cfg.SearchMaxResults < 0 || cfg.SearchCandidateMax < 0 || cfg.FuzzyMaxSnapshotMB < 16 || cfg.FreezeIntervalMs < 5 ||
			cfg.ListDefaultLimit < 1 || cfg.ListMaxLimit < cfg.ListDefaultLimit ||
			cfg.ResultsDefaultLimit < 1 || cfg.ResultsMaxLimit < cfg.ResultsDefaultLimit ||
			cfg.SetAllMax < 1 {
			return nil, fmt.Errorf("配置不合法(检查范围), 已回滚")
		}
		if err := cfg.Save(); err != nil {
			return nil, fmt.Errorf("配置保存失败: %v", err)
		}
		return map[string]interface{}{
			"changed": changed, "config": cfg, "saved": true,
		}, nil

	case "gg_search_xor":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		t, err := typeByName(getStr(args, "type"))
		if err != nil {
			return nil, err
		}
		if t.Size != 4 && t.Size != 8 {
			return nil, fmt.Errorf("Xor搜索仅支持 dword/qword")
		}
		val, err := parseValue(getStr(args, "value"), t)
		if err != nil {
			return nil, fmt.Errorf("值解析失败: %v", err)
		}
		refine, _ := args["refine"].(bool)
		rs, re, err := getRange(args)
		if err != nil {
			return nil, err
		}
		start := time.Now()
		res, err := session.XorSearch(val, t, getStr(args, "region"), rs, re, refine)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"xor": res, "elapsedMs": time.Since(start).Milliseconds(),
		}, nil

	case "gg_snapshot_results":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		snap, err := session.SaveSnapshot(getStr(args, "id"), getStr(args, "source"))
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"snapshot": map[string]interface{}{
				"id": snap.ID, "pid": snap.Pid, "type": snap.Type,
				"count": len(snap.Addrs), "source": snap.Source, "createdAt": snap.CreatedAt,
			},
			"tip": "用 gg_cross_analyze 与其他结果交叉分析",
		}, nil

	case "gg_list_snapshots":
		snaps, err := ListSnapshots()
		if err != nil {
			if os.IsNotExist(err) {
				return map[string]interface{}{"snapshots": []interface{}{}, "tip": "暂无快照"}, nil
			}
			return nil, err
		}
		var out []map[string]interface{}
		for _, s := range snaps {
			out = append(out, map[string]interface{}{
				"id": s.ID, "pid": s.Pid, "type": s.Type, "count": len(s.Addrs),
				"source": s.Source, "createdAt": s.CreatedAt,
			})
		}
		return map[string]interface{}{"snapshots": out, "total": len(out)}, nil

	case "gg_delete_snapshot":
		id := getStr(args, "id")
		if id == "all" {
			entries, err := os.ReadDir(SnapshotDir)
			if err != nil {
				return map[string]interface{}{"deleted": 0}, nil
			}
			n := 0
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".json") {
					os.Remove(fmt.Sprintf("%s/%s", SnapshotDir, e.Name()))
					n++
				}
			}
			return map[string]interface{}{"deleted": n, "tip": "全部快照已删除"}, nil
		}
		path := fmt.Sprintf("%s/%s.json", SnapshotDir, id)
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("快照不存在: %s", id)
		}
		return map[string]interface{}{"deleted": 1, "id": id}, nil

	case "gg_cross_analyze":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		a := getStr(args, "snapA")
		b := getStr(args, "snapB")
		if a == "" || b == "" {
			return nil, fmt.Errorf("snapA/snapB 不能为空(快照名或'current')")
		}
		gap := uint64(getInt(args, "gap", 16))
		if gap == 0 {
			gap = 16
		}
		start := time.Now()
		res, err := session.CrossAnalyze(a, b, gap, a == "current", b == "current")
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"cross": res, "elapsedMs": time.Since(start).Milliseconds(),
			"tip": "交集地址可直接 gg_set_results 修改; 相邻对提示结构体布局",
		}, nil

	case "gg_analyze_results":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		if session.Search == nil {
			return nil, fmt.Errorf("没有搜索结果, 先搜索")
		}
		maxScan := getInt(args, "maxScan", 0)
		gap := uint64(getInt(args, "gap", 16))
		if gap == 0 {
			gap = 16
		}
		start := time.Now()
		res := session.AnalyzeResults(maxScan, gap)
		return map[string]interface{}{
			"analysis": res, "elapsedMs": time.Since(start).Milliseconds(),
		}, nil

	case "gg_export_results":
		if err := requireTarget(); err != nil {
			return nil, err
		}
		if session.Search == nil {
			return nil, fmt.Errorf("没有搜索结果")
		}
		path := getStr(args, "path")
		if path == "" {
			path = fmt.Sprintf("/data/local/tmp/ggmcp/results_%d.json", time.Now().Unix())
		}
		type item struct {
			Index int    `json:"index"`
			Addr  string `json:"address"`
			Value string `json:"value"`
		}
		var items []item
		var addrs []uintptr
		if session.Search.FuzzyInit {
			addrs = session.FuzzyResults(cfg.ResultsMaxLimit)
		} else {
			addrs = session.Search.Candidates
		}
		buf := make([]byte, session.Search.Type.Size)
		for i, a := range addrs {
			v := "?"
			if session.Mem.ReadAt(a, buf) == nil {
				v = renderValue(buf, session.Search.Type)
			}
			items = append(items, item{Index: i, Addr: fmt.Sprintf("0x%x", a), Value: v})
		}
		export := map[string]interface{}{
			"pid":   session.Pid,
			"type":  session.Search.Type.Name,
			"total": len(items),
			"items": items,
		}
		data, err := json.MarshalIndent(export, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"path": path, "size": len(data), "items": len(items),
		}, nil

	case "gg_server_stop":
		// 延迟100ms退出, 确保响应先送达客户端
		go func() {
			time.Sleep(150 * time.Millisecond)
			os.Exit(0)
		}()
		return map[string]interface{}{
			"stopped": true,
			"tip":     "ggmcp服务器已退出(释放内存)。重启: adb shell 'su -c /data/local/tmp/ggmcp_ctl.sh start' 或重启手机",
		}, nil
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