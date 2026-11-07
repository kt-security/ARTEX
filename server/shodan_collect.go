package server

// Shodan 采集入口（kt-k8s#192 第 4/5 件）：CVE 列表「从 Shodan 采集」按钮的 HTTP
// 端点 + Agent 工具 shodan_collect。
//
// 采集器（shodan-collector）常驻主站 B 机，PG 队列消费、每页 1 credit。本模块只做
// 入队代理（POST {COLLECTOR_URL}/jobs，Bearer COLLECTOR_TOKEN），不做采集本身。
// 环境未配置时按钮/工具返回可读错误，不 panic。
//
// 队列语义（与 collector internal/queue 对齐）：
//   - 同 query 的 pending job 幂等合并，不重复扣 credit
//   - max_pages 每页 1 credit、100 条/页；断点续跑从 checkpoint 页继续

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/server/sigauth"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	envCollectorURL        = "COLLECTOR_URL"
	envCollectorToken      = "COLLECTOR_TOKEN"
	envCollectorSigningKey = "SIGAUTH_PRIVATE_KEY"

	collectorUserAgent = "artex-shodan-collect/1.0"
	collectorTimeout   = 15 * time.Second

	// 入队参数上限：max_pages 每页 1 credit，不能让一次调用把月度额度烧穿；
	// query/cve_id 长度上限用于挡住异常大请求，避免把采集器当任意文本通道。
	maxCollectPages    = 50
	maxCollectQueryLen = 512
	maxCollectCveIDLen = 64

	// 任务列表参数上限：limit 与采集器/前端契约一致（默认 50、上限 200），
	// offset 设硬上限，避免超大分页把采集器拖垮。
	maxCollectPageSize = 200
	maxCollectOffset   = 1_000_000
	maxCollectFilterQ  = 200
)

func collectorConfigured() bool {
	return strings.TrimSpace(os.Getenv(envCollectorURL)) != ""
}

// collectorAuthHeader 取调用采集器的 Authorization 值：优先 Ed25519 短时令牌
// （SIGAUTH_PRIVATE_KEY，私钥只在本机），回落共享 COLLECTOR_TOKEN（迁移期）。
func collectorAuthHeader() (string, error) {
	if kv := strings.TrimSpace(os.Getenv(envCollectorSigningKey)); kv != "" {
		signer, err := sigauth.ParsePriv(kv)
		if err != nil {
			return "", fmt.Errorf("SIGAUTH_PRIVATE_KEY 解析失败: %w", err)
		}
		tok, err := signer.Token()
		if err != nil {
			return "", err
		}
		return "Bearer " + tok, nil
	}
	if tok := strings.TrimSpace(os.Getenv(envCollectorToken)); tok != "" {
		return "Bearer " + tok, nil
	}
	return "", nil
}

func collectorConfiguredError() error {
	return fmt.Errorf(
		"管理员未配置 %s，或采集器凭据（%s / %s），采集功能暂不可用",
		envCollectorURL, envCollectorToken, envCollectorSigningKey,
	)
}

// collectorEnqueue 入队一个采集 job；返回 (jobID, error)。
// cveID 非空时原样带给采集器（落 shodan_collect_jobs.cve_id），供 CVE 详情页反查任务。
func collectorEnqueue(ctx context.Context, query string, maxPages int, reason, cveID, createdBy string) (int64, error) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv(envCollectorURL)), "/")
	if base == "" {
		return 0, collectorConfiguredError()
	}
	if maxPages <= 0 {
		maxPages = 5
	}
	if maxPages > maxCollectPages {
		maxPages = maxCollectPages
	}
	body, err := json.Marshal(map[string]any{
		"query": query, "max_pages": maxPages,
		"reason": reason, "cve_id": strings.TrimSpace(cveID), "created_by": createdBy,
	})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/jobs", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", collectorUserAgent)
	if auth, err := collectorAuthHeader(); err != nil {
		return 0, err
	} else if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	client := &http.Client{Timeout: collectorTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("采集器不可达: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("采集器入队 HTTP %d: %s", resp.StatusCode, string(rb))
	}
	var out struct {
		JobID int64  `json:"job_id"`
		Query string `json:"query"`
	}
	if err := json.Unmarshal(rb, &out); err != nil || out.JobID == 0 {
		return 0, fmt.Errorf("采集器响应异常: %s", string(rb))
	}
	return out.JobID, nil
}

// collectorStats 队列概览（GET /status）。
func collectorStats(ctx context.Context) (map[string]int64, error) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv(envCollectorURL)), "/")
	if base == "" {
		return nil, collectorConfiguredError()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", collectorUserAgent)
	if auth, err := collectorAuthHeader(); err != nil {
		return nil, err
	} else if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := (&http.Client{Timeout: collectorTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("采集器不可达: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("采集器状态 HTTP %d", resp.StatusCode)
	}
	var out map[string]int64
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// collectorGet 向采集器发一条带鉴权的 GET，把 JSON 响应反序列化进 out。
// 逐任务列表/详情共用（kt-vuln#73）：鉴权头、UA、超时、错误文案只写一份。
func collectorGet(ctx context.Context, path string, out any) error {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv(envCollectorURL)), "/")
	if base == "" {
		return collectorConfiguredError()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", collectorUserAgent)
	if auth, err := collectorAuthHeader(); err != nil {
		return err
	} else if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := (&http.Client{Timeout: collectorTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("采集器不可达: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errCollectorNotFound
	}
	if resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return fmt.Errorf("采集器 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// errCollectorNotFound 采集器回 404（job 不存在），与「采集器不可达」区分开。
var errCollectorNotFound = errors.New("任务不存在")

// errJobNotCancellable 采集器回 409：任务已开跑或已结束，不能撤销。
var errJobNotCancellable = errors.New("任务已开始或已结束，不能撤销")

// collectorCancel 撤销一条待采集 job（kt-vuln#73：低质量查询不用继续烧 credit）。
func collectorCancel(ctx context.Context, id int64) error {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv(envCollectorURL)), "/")
	if base == "" {
		return collectorConfiguredError()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/jobs/"+strconv.FormatInt(id, 10)+"/cancel", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", collectorUserAgent)
	if auth, err := collectorAuthHeader(); err != nil {
		return err
	} else if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := (&http.Client{Timeout: collectorTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("采集器不可达: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return errCollectorNotFound
	case http.StatusConflict:
		return errJobNotCancellable
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return fmt.Errorf("采集器 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
}

// queueCloudJob 是采集器任务（shodan_collect_jobs 一行）的读模型镜像，字段与
// collector internal/queue.JobRecord 的 JSON 对齐。Agent 工具用它渲染最近任务。
type queueCloudJob struct {
	ID            int64  `json:"id"`
	Query         string `json:"query"`
	MaxPages      int    `json:"max_pages"`
	CveID         string `json:"cve_id,omitempty"`
	CreatedBy     string `json:"created_by"`
	Status        string `json:"status"`
	LastPage      int    `json:"last_page"`
	CreditsSpent  int64  `json:"credits_spent"`
	AssetsWritten int64  `json:"assets_written"`
	Note          string `json:"note,omitempty"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ---- HTTP 端点（admin 门：采集花 credit，只允许管理员触发）----

func (s *Server) shodanCollect(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Query    string `json:"query"`
		MaxPages int    `json:"max_pages"`
		CveID    string `json:"cve_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	in.Query = strings.TrimSpace(in.Query)
	if in.Query == "" {
		writeErr(w, http.StatusBadRequest, "query 必填（Shodan 查询体，如 \"log4j country:CN\"）")
		return
	}
	if len(in.Query) > maxCollectQueryLen {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("query 过长（上限 %d 字符）", maxCollectQueryLen))
		return
	}
	in.CveID = strings.TrimSpace(in.CveID)
	if len(in.CveID) > maxCollectCveIDLen {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("cve_id 过长（上限 %d 字符）", maxCollectCveIDLen))
		return
	}
	reason := "artex:manual"
	if in.CveID != "" {
		reason = "artex:cve:" + in.CveID
	}
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()
	jobID, err := collectorEnqueue(ctx, in.Query, in.MaxPages, reason, in.CveID, "artex-web")
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"job_id": jobID, "query": in.Query, "cve_id": in.CveID,
		"message": fmt.Sprintf("已入队（job #%d），采集器将按队列执行并自动入库", jobID),
	})
}

// shodanCollectJobs GET /api/vuln/shodan-collect/jobs
// 逐任务列表（kt-vuln#73 可观测性）：前端「采集任务」页的数据源。
// 查询参数 status / cve_id / q / limit / offset 先在本站收敛（白名单、长度、
// 取值范围），再用 url.Values 编码透传给采集器；不把原始输入直接拼进上游 URL。
func (s *Server) shodanCollectJobs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	vals := url.Values{}

	status := strings.TrimSpace(q.Get("status"))
	switch status {
	case "", "pending", "running", "done", "failed", "cancelled":
		if status != "" {
			vals.Set("status", status)
		}
	default:
		writeErr(w, http.StatusBadRequest, "status 取值非法")
		return
	}

	cveID := strings.TrimSpace(q.Get("cve_id"))
	if len(cveID) > maxCollectCveIDLen {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("cve_id 过长（上限 %d 字符）", maxCollectCveIDLen))
		return
	}
	if cveID != "" {
		vals.Set("cve_id", cveID)
	}

	keyword := strings.TrimSpace(q.Get("q"))
	if len(keyword) > maxCollectFilterQ {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("q 过长（上限 %d 字符）", maxCollectFilterQ))
		return
	}
	if keyword != "" {
		vals.Set("q", keyword)
	}

	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "limit 必须是正整数")
			return
		}
		if n > maxCollectPageSize {
			n = maxCollectPageSize
		}
		vals.Set("limit", strconv.Itoa(n))
	}
	if raw := strings.TrimSpace(q.Get("offset")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "offset 必须是非负整数")
			return
		}
		if n > maxCollectOffset {
			n = maxCollectOffset
		}
		vals.Set("offset", strconv.Itoa(n))
	}

	path := "/jobs"
	if enc := vals.Encode(); enc != "" {
		path += "?" + enc
	}
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()
	var out struct {
		Items  []json.RawMessage `json:"items"`
		Total  int64             `json:"total"`
		Limit  int               `json:"limit"`
		Offset int               `json:"offset"`
	}
	if err := collectorGet(ctx, path, &out); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}

// shodanCollectJob GET /api/vuln/shodan-collect/jobs/{id} 单条任务详情（前端轮询/详情用）。
func (s *Server) shodanCollectJob(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "任务 id 非法")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()
	var out json.RawMessage
	if err := collectorGet(ctx, "/jobs/"+strconv.FormatInt(id, 10), &out); err != nil {
		if errors.Is(err, errCollectorNotFound) {
			writeErr(w, http.StatusNotFound, "任务不存在")
			return
		}
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out)
}

func (s *Server) shodanCollectStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()
	stats, err := collectorStats(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// shodanCollectCancel POST /api/vuln/shodan-collect/jobs/{id}/cancel
// 撤销待采集任务：只在 pending 阶段可撤（已开跑会烧 credit，不打断）。
func (s *Server) shodanCollectCancel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "任务 id 非法")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()
	if err := collectorCancel(ctx, id); err != nil {
		switch {
		case errors.Is(err, errCollectorNotFound):
			writeErr(w, http.StatusNotFound, "任务不存在")
		case errors.Is(err, errJobNotCancellable):
			writeErr(w, http.StatusConflict, err.Error())
		default:
			writeErr(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"job_id": id, "status": "cancelled"})
}

// ---- Agent 工具 shodan_collect（与 vuln 工具同模式，绑 auto+worker）----

func (s *Server) toolShodanCollect() actool.CoreTool {
	desc := "把一个 Shodan 查询体加入采集队列（按 CVE 价值采集互联网资产并自动入库 kt-vuln）。\n" +
		"• query 是 Shodan 查询语法，如 \"log4j country:CN\"、\"nginx country:US\"；每个不同 query 首次 1 credit\n" +
		"• max_pages 每页 1 credit、100 条/页，默认 5；同 query 的 pending job 幂等合并，不会重复扣费\n" +
		"• 采集是异步的：本工具只入队，完成后资产出现在 vuln_search_assets / 资产列表（source=shodan）\n" +
		"• credit 是月度订阅额度（用不完会作废），对高价值 CVE 优先采集；status 可查队列概览"
	schema := objSchema(map[string]any{
		"query":     strParam("Shodan 查询体，如 \"log4j country:CN\"（支持 product/country/port 等 filter）"),
		"max_pages": map[string]any{"type": "integer", "description": "最多翻页数，每页 1 credit、100 条，默认 5"},
		"cve_id":    strParam("可选：关联的 CVE 编号，写进入队原因便于溯源"),
		"status":    map[string]any{"type": "boolean", "description": "true 时不入队，只返回队列概览"},
	}, "query")
	return roTool("shodan_collect", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Query    string `json:"query"`
			MaxPages int    `json:"max_pages"`
			CveID    string `json:"cve_id"`
			Status   bool   `json:"status"`
		}
		_ = json.Unmarshal(in, &a)
		if a.Status {
			// status=true 不只回聚合计数，还带最近 5 条任务：Agent 排查「我提交的那条
			// 跑没跑」时，光看 pending/running 计数没用（kt-vuln#73）。
			stats, err := collectorStats(ctx)
			if err != nil {
				return actool.Result{}, err
			}
			var recent struct {
				Items []queueCloudJob `json:"items"`
				Total int64           `json:"total"`
			}
			if err := collectorGet(ctx, "/jobs?limit=5", &recent); err != nil {
				// 列表失败不掩盖概览：能给的先给。
				b, _ := json.MarshalIndent(stats, "", " ")
				return actool.Text("采集队列概览（按状态计数的 job 数）：\n" + string(b) +
					"\n（最近任务列表拉取失败：" + err.Error() + "）"), nil
			}
			b, _ := json.MarshalIndent(struct {
				Stats  map[string]int64 `json:"stats"`
				Total  int64            `json:"total"`
				Recent []queueCloudJob  `json:"recent"`
			}{stats, recent.Total, recent.Items}, "", " ")
			return actool.Text("采集队列概览 + 最近 5 条任务：\n" + string(b)), nil
		}
		a.Query = strings.TrimSpace(a.Query)
		if a.Query == "" {
			return actool.Result{}, fmt.Errorf("query 必填（Shodan 查询体，如 \"log4j country:CN\"）")
		}
		if len(a.Query) > maxCollectQueryLen {
			return actool.Result{}, fmt.Errorf("query 过长（上限 %d 字符）", maxCollectQueryLen)
		}
		a.CveID = strings.TrimSpace(a.CveID)
		if len(a.CveID) > maxCollectCveIDLen {
			return actool.Result{}, fmt.Errorf("cve_id 过长（上限 %d 字符）", maxCollectCveIDLen)
		}
		reason := "artex:agent"
		if a.CveID != "" {
			reason = "artex:cve:" + a.CveID
		}
		jobID, err := collectorEnqueue(ctx, a.Query, a.MaxPages, reason, a.CveID, "artex-agent")
		if err != nil {
			return actool.Result{}, err
		}
		return actool.Text(fmt.Sprintf("已入队采集（job #%d）：query=%q。采集是异步的，完成后资产自动入库（source=shodan），可用 vuln_search_assets 查询。", jobID, a.Query)), nil
	})
}

// faviconOverride 提供本站专属图标（FAVICON_B64，PNG base64）。
func (s *Server) faviconOverride(w http.ResponseWriter, r *http.Request) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("FAVICON_B64")))
	if err != nil || len(raw) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(raw)
}

// toolQueryCveCatalog query_cve_catalog（#61 D3）：自然语言→结构化筛选的全量目录查询工具。
func (s *Server) toolQueryCveCatalog() actool.CoreTool {
	desc := "查询 kt-vuln 全量 CVE 目录（28 万+ 条 NVD 字典），支持组合筛选与排序。\n" +
		"参数示例：「2025 年以来 CVSS≥9 的 Apache 漏洞」→ published_from=2025-01-01, severity_min=9, vendor=apache。\n" +
		"sort: severity|published|cve_id|epss|risk（risk=KEV→EPSS→CVSS→时间 组合优先）；order: desc|asc。只读，实时查询不落副本。"
	schema := objSchema(map[string]any{
		"q":              strParam("关键词（匹配 cve_id/标题模糊）"),
		"published_from": strParam("发布日期起（YYYY-MM-DD，含）"),
		"published_to":   strParam("发布日期止（YYYY-MM-DD，含）"),
		"severity_min":   map[string]any{"type": "number", "description": "CVSS 下限 0-10"},
		"severity_max":   map[string]any{"type": "number", "description": "CVSS 上限 0-10"},
		"vendor":         strParam("厂商（精确匹配，NVD CPE 解析回填）"),
		"product":        strParam("产品（精确匹配）"),
		"cwe":            strParam("弱点类型，如 CWE-89"),
		"year":           map[string]any{"type": "integer", "description": "发布年份"},
		"sort":           map[string]any{"type": "string", "enum": []string{"severity", "published", "cve_id", "epss", "risk"}},
		"order":          map[string]any{"type": "string", "enum": []string{"desc", "asc"}},
		"page":           map[string]any{"type": "integer", "description": "页码，默认 1"},
		"page_size":      map[string]any{"type": "integer", "description": "每页条数，默认 20、上限 200"},
	})
	return roTool("query_cve_catalog", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Q             string   `json:"q"`
			PublishedFrom string   `json:"published_from"`
			PublishedTo   string   `json:"published_to"`
			SeverityMin   *float64 `json:"severity_min"`
			SeverityMax   *float64 `json:"severity_max"`
			Vendor        string   `json:"vendor"`
			Product       string   `json:"product"`
			Cwe           string   `json:"cwe"`
			Year          int      `json:"year"`
			Sort          string   `json:"sort"`
			Order         string   `json:"order"`
			Page          int      `json:"page"`
			PageSize      int      `json:"page_size"`
		}
		_ = json.Unmarshal(in, &a)
		q := url.Values{}
		set := func(k, v string) {
			if v != "" {
				q.Set(k, v)
			}
		}
		set("q", strings.TrimSpace(a.Q))
		set("published_from", a.PublishedFrom)
		set("published_to", a.PublishedTo)
		if a.SeverityMin != nil {
			q.Set("severity_min", strconv.FormatFloat(*a.SeverityMin, 'f', -1, 64))
		}
		if a.SeverityMax != nil {
			q.Set("severity_max", strconv.FormatFloat(*a.SeverityMax, 'f', -1, 64))
		}
		set("vendor", strings.TrimSpace(a.Vendor))
		set("product", strings.TrimSpace(a.Product))
		set("cwe", strings.ToUpper(strings.TrimSpace(a.Cwe)))
		if a.Year > 0 {
			q.Set("year", strconv.Itoa(a.Year))
		}
		set("sort", a.Sort)
		set("order", a.Order)
		if a.Page < 1 {
			a.Page = 1
		}
		if a.PageSize < 1 {
			a.PageSize = 20
		}
		if a.PageSize > 200 {
			a.PageSize = 200
		}
		q.Set("page", strconv.Itoa(a.Page))
		q.Set("page_size", strconv.Itoa(a.PageSize))
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		var resp struct {
			Items []map[string]any `json:"items"`
			Total int64            `json:"total"`
		}
		if err := vulnGet(cctx, "/api/cve-catalog", q, &resp); err != nil {
			return actool.Result{}, err
		}
		b, _ := json.MarshalIndent(map[string]any{"total": resp.Total, "page": a.Page, "items": resp.Items}, "", " ")
		return actool.Text(string(b)), nil
	})
}
