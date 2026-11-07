// 假 shodan-collector：给「采集任务」页做本地联调用，不花 credit、不碰 Shodan。
//
// 与真采集器（KTAIorg/shodan-collector）的 HTTP 面一致：
//   POST   /jobs            入队（同 query 幂等合并）
//   GET    /jobs            列表（status/cve_id/q/limit/offset）
//   GET    /jobs/{id}       详情
//   POST   /jobs/{id}/cancel 撤销 pending（running 回 409）
//   GET    /status          聚合计数
// 额外行为：pending 的 job 每 3 秒被"认领"→ running，每 2 秒推进一页，跑满 max_pages
// 后变 done 并写入假的 assets_written/credits_spent；query 里带 fail 的 job 会失败，
// 用来演示失败原因那一列。
//
// 用法：
//   go run ./scripts/dev/fake-collector -addr :44852 -token dev-token
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type job struct {
	ID            int64     `json:"id"`
	Query         string    `json:"query"`
	MaxPages      int       `json:"max_pages"`
	Priority      int       `json:"priority"`
	Reason        string    `json:"reason"`
	CveID         string    `json:"cve_id,omitempty"`
	CreatedBy     string    `json:"created_by"`
	Status        string    `json:"status"`
	LastPage      int       `json:"last_page"`
	CreditsSpent  int64     `json:"credits_spent"`
	AssetsWritten int64     `json:"assets_written"`
	Note          string    `json:"note,omitempty"`
	ClaimedBy     string    `json:"claimed_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type store struct {
	mu   sync.Mutex
	jobs map[int64]*job
	next int64
}

func newStore() *store { return &store{jobs: map[int64]*job{}, next: 1} }

func (s *store) enqueue(in job) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.Query == in.Query && j.Status == "pending" {
			if j.CveID == "" && in.CveID != "" {
				j.CveID = in.CveID
				j.UpdatedAt = time.Now()
			}
			return j.ID, false
		}
	}
	now := time.Now()
	in.ID = s.next
	s.next++
	in.Status = "pending"
	in.CreatedAt, in.UpdatedAt = now, now
	cp := in
	s.jobs[in.ID] = &cp
	return in.ID, true
}

func (s *store) list(status, cveID, q string, limit, offset int) ([]job, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]job, 0, len(s.jobs))
	for _, j := range s.jobs {
		if status != "" && j.Status != status {
			continue
		}
		if cveID != "" && j.CveID != cveID {
			continue
		}
		if q != "" && !strings.Contains(j.Query, q) {
			continue
		}
		out = append(out, *j)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].ID > out[k].ID })
	total := int64(len(out))
	if offset > len(out) {
		offset = len(out)
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[offset:end], total
}

func (s *store) get(id int64) *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		cp := *j
		return &cp
	}
	return nil
}

func (s *store) cancel(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok || j.Status != "pending" {
		return false
	}
	j.Status = "cancelled"
	j.Note = "已撤销"
	j.UpdatedAt = time.Now()
	return true
}

func (s *store) stats() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int64{}
	for _, j := range s.jobs {
		out[j.Status]++
	}
	return out
}

// tick 模拟 worker：pending → running → 每 2 秒一页 → done/failed。
func (s *store) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		switch j.Status {
		case "pending":
			if time.Since(j.CreatedAt) >= 3*time.Second {
				j.Status, j.ClaimedBy, j.UpdatedAt = "running", "fake-worker-1", time.Now()
			}
		case "running":
			j.LastPage++
			j.CreditsSpent++
			j.AssetsWritten += 100
			j.UpdatedAt = time.Now()
			if strings.Contains(strings.ToLower(j.Query), "fail") {
				j.Status, j.Note = "failed", fmt.Sprintf("第 %d 页 search 失败: 429 Too Many Requests", j.LastPage)
			} else if j.LastPage >= j.MaxPages {
				j.Status, j.Note = "done", "ok"
			}
		}
	}
}

func main() {
	addr := flag.String("addr", ":44852", "监听地址")
	token := flag.String("token", "dev-token", "共享令牌（Bearer）")
	flag.Parse()

	st := newStore()
	go func() {
		for range time.Tick(2 * time.Second) {
			st.tick()
		}
	}()

	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != *token {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /jobs", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var in job
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Query) == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if in.MaxPages <= 0 {
			in.MaxPages = 5
		}
		id, created := st.enqueue(in)
		writeJSON(w, map[string]any{"job_id": id, "query": in.Query, "merged": !created})
	})
	mux.HandleFunc("GET /jobs", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		items, total := st.list(q.Get("status"), q.Get("cve_id"), q.Get("q"), limit, offset)
		writeJSON(w, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
	})
	mux.HandleFunc("GET /jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		j := st.get(id)
		if j == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, j)
	})
	mux.HandleFunc("POST /jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if !st.cancel(id) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		writeJSON(w, map[string]any{"job_id": id, "status": "cancelled"})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		writeJSON(w, st.stats())
	})

	log.Printf("fake-collector listening on %s (token=%s)", *addr, *token)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}

var _ = fmt.Sprintf
