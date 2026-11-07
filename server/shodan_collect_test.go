package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newCollectorTestUpstream 起一个假 shodan-collector：记录收到的请求，按 handler 回包。
// 采集器真实实现见 KTAIorg/shodan-collector（GET /jobs、/jobs/{id}、POST /jobs/{id}/cancel）。
func newCollectorTestUpstream(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv(envCollectorURL, srv.URL)
	t.Setenv(envCollectorToken, "test-token")
	return srv
}

// TestShodanCollectJobsProxy 覆盖 kt-vuln#73 列表代理：过滤参数原样透传、鉴权头带上、
// 响应结构（items/total）不丢失。
func TestShodanCollectJobsProxy(t *testing.T) {
	var got struct {
		path     string
		query    string
		auth     string
		ua       string
		rawQuery string
	}
	newCollectorTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.rawQuery = r.URL.RawQuery
		got.auth = r.Header.Get("Authorization")
		got.ua = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"items":[{"id":16,"query":"solr country:US","status":"done","max_pages":5,`+
			`"last_page":5,"assets_written":500,"credits_spent":5,"note":"ok","cve_id":"CVE-2019-17558"}],"total":1}`)
	})

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet,
		"/api/vuln/shodan-collect/jobs?status=done&cve_id=CVE-2019-17558&limit=10&offset=20", nil)
	rec := httptest.NewRecorder()
	s.shodanCollectJobs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，得到 %d: %s", rec.Code, rec.Body.String())
	}
	if got.path != "/jobs" {
		t.Fatalf("上游路径应为 /jobs，得到 %q", got.path)
	}
	for _, want := range []string{"status=done", "cve_id=CVE-2019-17558", "limit=10", "offset=20"} {
		if !strings.Contains(got.rawQuery, want) {
			t.Fatalf("上游 query 缺少 %q：%q", want, got.rawQuery)
		}
	}
	if got.auth != "Bearer test-token" {
		t.Fatalf("鉴权头应为 Bearer test-token，得到 %q", got.auth)
	}
	if got.ua != collectorUserAgent {
		t.Fatalf("UA 应为 %q，得到 %q", collectorUserAgent, got.ua)
	}

	var out struct {
		Items []map[string]any `json:"items"`
		Total int64            `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if out.Total != 1 || len(out.Items) != 1 {
		t.Fatalf("items/total 未透传: %+v", out)
	}
	if out.Items[0]["assets_written"].(float64) != 500 || out.Items[0]["cve_id"] != "CVE-2019-17558" {
		t.Fatalf("任务字段缺失: %+v", out.Items[0])
	}
}

// TestShodanCollectJobDetailNotFound 区分 404（job 不存在）与 502（采集器挂）。
func TestShodanCollectJobDetailNotFound(t *testing.T) {
	newCollectorTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/vuln/shodan-collect/jobs/999", nil)
	req.SetPathValue("id", "999")
	rec := httptest.NewRecorder()
	s.shodanCollectJob(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("期望 404，得到 %d: %s", rec.Code, rec.Body.String())
	}
}

// TestShodanCollectEnqueueCarriesCveID 入队必须把 cve_id 带给采集器：CVE 详情页
// 反查任务全靠它（只写 reason 字符串无法索引）。
func TestShodanCollectEnqueueCarriesCveID(t *testing.T) {
	var body map[string]any
	newCollectorTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"job_id":21,"query":"product:\"Apache Solr\""}`)
	})

	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/vuln/shodan-collect",
		strings.NewReader(`{"query":"product:\"Apache Solr\" country:US","cve_id":"CVE-2019-17558","max_pages":3}`))
	rec := httptest.NewRecorder()
	s.shodanCollect(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，得到 %d: %s", rec.Code, rec.Body.String())
	}
	if body["cve_id"] != "CVE-2019-17558" {
		t.Fatalf("入队未带 cve_id: %+v", body)
	}
	if body["reason"] != "artex:cve:CVE-2019-17558" {
		t.Fatalf("reason 语义变了: %+v", body["reason"])
	}
	if body["max_pages"].(float64) != 3 {
		t.Fatalf("max_pages 未透传: %+v", body["max_pages"])
	}
}

// TestShodanCollectCancelConflict 撤销已被认领的任务要回 409，而不是假装成功。
func TestShodanCollectCancelConflict(t *testing.T) {
	newCollectorTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/cancel") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusConflict)
	})

	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/vuln/shodan-collect/jobs/16/cancel", nil)
	req.SetPathValue("id", "16")
	rec := httptest.NewRecorder()
	s.shodanCollectCancel(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("期望 409，得到 %d: %s", rec.Code, rec.Body.String())
	}
}

// TestShodanCollectNotConfigured 未配置采集器时给可读错误而不是 500 崩。
func TestShodanCollectNotConfigured(t *testing.T) {
	t.Setenv(envCollectorURL, "")
	t.Setenv(envCollectorToken, "")

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/vuln/shodan-collect/jobs", nil)
	rec := httptest.NewRecorder()
	s.shodanCollectJobs(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("期望 502，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), envCollectorURL) {
		t.Fatalf("错误信息应点名缺失的环境变量: %s", rec.Body.String())
	}
}

// TestShodanCollectJobsRejectsInvalidFilters 列表参数在本站收敛，不把原始输入
// 直接拼给采集器：非法 status / 负 limit / 超长 q 一律 400。
func TestShodanCollectJobsRejectsInvalidFilters(t *testing.T) {
	cases := []string{
		"?status=deleted",
		"?limit=0",
		"?limit=abc",
		"?offset=-1",
		"?q=" + strings.Repeat("a", maxCollectFilterQ+1),
		"?cve_id=" + strings.Repeat("C", maxCollectCveIDLen+1),
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			// 不启上游：参数校验应先于任何网络调用。
			s := &Server{}
			req := httptest.NewRequest(http.MethodGet, "/api/vuln/shodan-collect/jobs"+raw, nil)
			rec := httptest.NewRecorder()
			s.shodanCollectJobs(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s 期望 400，得到 %d: %s", raw, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestShodanCollectJobsClampsPageSize 超大 limit/offset 收敛到上限，再编码透传。
func TestShodanCollectJobsClampsPageSize(t *testing.T) {
	var gotQuery string
	newCollectorTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"items":[],"total":0}`)
	})

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet,
		"/api/vuln/shodan-collect/jobs?limit=9999&offset=99999999&status=running", nil)
	rec := httptest.NewRecorder()
	s.shodanCollectJobs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，得到 %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(gotQuery, "limit=200") {
		t.Fatalf("limit 未收敛到 %d: %q", maxCollectPageSize, gotQuery)
	}
	if !strings.Contains(gotQuery, "offset=1000000") {
		t.Fatalf("offset 未收敛到 %d: %q", maxCollectOffset, gotQuery)
	}
	if !strings.Contains(gotQuery, "status=running") {
		t.Fatalf("status 未透传: %q", gotQuery)
	}
}

// TestShodanCollectCapsMaxPages 入队页数封顶，避免一次调用烧穿月度 credit。
func TestShodanCollectCapsMaxPages(t *testing.T) {
	var body map[string]any
	newCollectorTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"job_id":22,"query":"nginx"}`)
	})

	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/vuln/shodan-collect",
		strings.NewReader(`{"query":"nginx","max_pages":100000}`))
	rec := httptest.NewRecorder()
	s.shodanCollect(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，得到 %d: %s", rec.Code, rec.Body.String())
	}
	if body["max_pages"].(float64) != maxCollectPages {
		t.Fatalf("max_pages 应封顶为 %d，得到 %+v", maxCollectPages, body["max_pages"])
	}
}

// TestShodanCollectRejectsOversizedQuery 超长 query/cve_id 在入队前拒绝。
func TestShodanCollectRejectsOversizedQuery(t *testing.T) {
	s := &Server{}
	longQuery := strings.NewReader(`{"query":"` + strings.Repeat("a", maxCollectQueryLen+1) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/vuln/shodan-collect", longQuery)
	rec := httptest.NewRecorder()
	s.shodanCollect(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超长 query 期望 400，得到 %d: %s", rec.Code, rec.Body.String())
	}

	longCve := strings.NewReader(`{"query":"nginx","cve_id":"` + strings.Repeat("C", maxCollectCveIDLen+1) + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/vuln/shodan-collect", longCve)
	rec = httptest.NewRecorder()
	s.shodanCollect(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超长 cve_id 期望 400，得到 %d: %s", rec.Code, rec.Body.String())
	}
}
