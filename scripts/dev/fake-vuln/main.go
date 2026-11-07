// 假 kt-vuln 后端：给本地联调 CVE 列表/详情/采集入口用，不碰线上、不需要 KT Identity。
//
// 只实现前端「Vuln情报站」用到的读接口：
//   GET /api/cves                  关注清单（带 affected 影响组件，采集弹窗靠它预填精准指纹）
//   GET /api/cve-catalog           全量目录（分页，带 vendor/product）
//   GET /api/cve-catalog/years     年份桶
//   GET /api/assets                资产目录（本地恒为空；采集任务是假采集器，不写这里）
//
// 鉴权：ARTEX 代理只要求请求带上非空的 X-Identity-Token（不解析），所以本地随便填一个。
//
// 用法：
//   go run ./scripts/dev/fake-vuln -addr :44853
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strconv"
	"time"
)

// cve 关注清单条目：字段与 lib/vuln.ts 的 VulnCve 对齐。
type cve struct {
	CveID    string              `json:"cve_id"`
	Title    string              `json:"title"`
	Category string              `json:"category"`
	Severity float64             `json:"severity"`
	Kev      bool                `json:"kev"`
	Affected map[string][]string `json:"affected"`
	Surface  map[string]int      `json:"surface"`
}

func seed() []cve {
	return []cve{
		{
			CveID: "CVE-2019-17558", Title: "Apache Solr Velocity 模板远程代码执行", Category: "solr",
			Severity: 8.1, Kev: true,
			Affected: map[string][]string{"Apache Solr": {"5.0.0-8.3.1"}},
			Surface:  map[string]int{"vulnerable": 3, "executable": 1, "patched": 0, "not_applicable": 0, "unknown": 2},
		},
		{
			CveID: "CVE-2021-25646", Title: "Apache Druid 认证缺失导致命令执行", Category: "druid",
			Severity: 9.8, Kev: true,
			Affected: map[string][]string{"Apache Druid": {"0.16.0-0.20.1"}},
			Surface:  map[string]int{"vulnerable": 1, "executable": 0, "patched": 1, "not_applicable": 0, "unknown": 0},
		},
		{
			CveID: "CVE-2021-44228", Title: "Log4j2 JNDI 注入（Log4Shell）", Category: "log4j",
			Severity: 10.0, Kev: true,
			Affected: map[string][]string{"Apache Log4j": {"2.0.0-2.14.1"}},
			Surface:  map[string]int{"vulnerable": 7, "executable": 4, "patched": 2, "not_applicable": 0, "unknown": 5},
		},
	}
}

func main() {
	addr := flag.String("addr", ":44853", "监听地址")
	flag.Parse()

	items := seed()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cves", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": items, "total": len(items)})
	})

	// 全量目录：把同 3 条当目录条目返回，字段与 VulnCveCatalogItem 对齐。
	mux.HandleFunc("GET /api/cve-catalog", func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		if size < 1 || size > 200 {
			size = 50
		}
		out := make([]map[string]any, 0, len(items))
		for _, c := range items {
			product := ""
			affected := []string{}
			for k, v := range c.Affected {
				product = k
				affected = v
			}
			out = append(out, map[string]any{
				"cve_id": c.CveID, "title": c.Title, "severity": c.Severity, "kev": c.Kev,
				"published": "2021-12-10", "published_year": 2021, "source": "nvd",
				"vendor": "Apache", "product": product, "cwe": []string{"CWE-917"},
				"epss": 0.94, "affected_version_range": affected,
			})
		}
		writeJSON(w, map[string]any{"items": out, "total": len(out), "page": page, "page_size": size})
	})
	mux.HandleFunc("GET /api/cve-catalog/years", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{
			{"year": 2021, "count": 2}, {"year": 2019, "count": 1},
		}})
	})
	// 资产目录：本地不模拟采集结果，返回空表（采集任务本身由假采集器跑）。
	mux.HandleFunc("GET /api/assets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []any{}, "total": 0})
	})
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ok", "fake": true, "at": time.Now()})
	})

	log.Printf("fake-vuln listening on %s（3 条 CVE，够点采集/详情/拦截）", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}
