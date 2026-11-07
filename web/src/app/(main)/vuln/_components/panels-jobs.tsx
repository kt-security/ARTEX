"use client";

// 采集任务面板（kt-vuln#73 可观测性主线）。
//
// 背景：CVE 列表点「采集」后只回一条 toast，之后任务在哪里都看不到——后端
// shodan_collect_jobs 数据齐全（status/last_page/credits_spent/assets_written/note），
// 但没有逐任务接口、也没有前端入口，用户流程直接断掉。
//
// 本面板只做"看得见"这一件事：列表 + 进度 + 额度 + 失败原因 + 按 CVE 反查。
// 数据源是 ARTEX 代理 GET /api/vuln/shodan-collect/jobs（admin 门，采集花 credit）。
//
// 刷新策略：有 pending/running 时 2s 轮询（单任务约 20 秒跑完 5 页，看得见推进过程）；
// 全部终态时 10s 兜底；页面隐藏时停表，回来立即补一次。

import * as React from "react";

import Link from "next/link";

import { ExternalLinkIcon, RefreshCwIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useIsAdmin } from "@/hooks/use-is-admin";
import { cn } from "@/lib/utils";
import { type VulnCollectJob, vuln } from "@/lib/vuln";

const ACTIVE_POLL_MS = 2_000;
const IDLE_POLL_MS = 10_000;
const PAGE_SIZE = 50;

const STATUS_OPTIONS: { value: string; label: string }[] = [
  { value: "all", label: "全部状态" },
  { value: "pending", label: "待采集" },
  { value: "running", label: "采集中" },
  { value: "done", label: "已完成" },
  { value: "failed", label: "失败" },
  { value: "cancelled", label: "已取消" },
];

// 状态 → 文案与配色。未知状态原样展示，不吞字段。
const STATUS_STYLE: Record<string, { label: string; cls: string }> = {
  pending: { label: "待采集", cls: "bg-amber-500/15 text-amber-600 dark:text-amber-400" },
  running: { label: "采集中", cls: "bg-sky-500/15 text-sky-600 dark:text-sky-400" },
  done: { label: "已完成", cls: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" },
  failed: { label: "失败", cls: "bg-rose-500/15 text-rose-600 dark:text-rose-400" },
  cancelled: { label: "已取消", cls: "bg-muted text-muted-foreground" },
};

function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLE[status];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium",
        style?.cls ?? "bg-muted text-muted-foreground",
      )}
    >
      {style?.label ?? status}
    </span>
  );
}

function isActive(job: VulnCollectJob): boolean {
  return job.status === "pending" || job.status === "running";
}

function fmtTime(value?: string): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function VulnCollectJobsPanel({
  refreshKey,
  initialCve,
}: {
  refreshKey: number;
  /** 从 CVE 详情跳进来时带上该 CVE，落到筛选条件上（?cve=CVE-xxxx）。 */
  initialCve?: string;
}) {
  const [status, setStatus] = React.useState("all");
  const [cveId, setCveId] = React.useState("");
  const [query, setQuery] = React.useState("");
  // 筛选草稿与已提交条件分开：输入过程中不打服务端（列表每 2s 轮询，避免抖动）。
  const [applied, setApplied] = React.useState<{ status?: string; cve_id?: string; q?: string }>({});
  const [jobs, setJobs] = React.useState<VulnCollectJob[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [cancelling, setCancelling] = React.useState<number | null>(null);
  const reqRef = React.useRef(0);
  const abortRef = React.useRef<AbortController | null>(null);

  // 卸载时取消在途请求，避免轮询/翻页的迟到响应继续 setState。
  React.useEffect(
    () => () => {
      abortRef.current?.abort();
    },
    [],
  );

  const load = React.useCallback(
    async (opts: { silent?: boolean } = {}) => {
      const seq = ++reqRef.current;
      // 新请求取代旧请求：轮询与手动刷新同时发生时只保留最新一份。
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      if (!opts.silent) setLoading(true);
      try {
        const r = await vuln.shodanCollectJobs(
          { ...applied, limit: PAGE_SIZE, offset: page * PAGE_SIZE },
          { signal: controller.signal },
        );
        if (seq !== reqRef.current || controller.signal.aborted) return;
        setJobs(r.items);
        setTotal(r.total);
        setError("");
      } catch (e) {
        if (controller.signal.aborted || seq !== reqRef.current) return;
        const msg = String((e as Error)?.message ?? e);
        setError(msg);
        if (!opts.silent) toast.error(`采集任务列表加载失败：${msg}`);
      } finally {
        if (seq === reqRef.current && !controller.signal.aborted) setLoading(false);
      }
    },
    [applied, page],
  );

  // ?cve= 深链：只吃一次，之后用户自己改筛选不再被覆盖。
  const [cveApplied, setCveApplied] = React.useState(false);
  React.useEffect(() => {
    if (cveApplied || !initialCve) return;
    setCveId(initialCve);
    setApplied({ cve_id: initialCve });
    setCveApplied(true);
  }, [initialCve, cveApplied]);

  React.useEffect(() => {
    void load();
  }, [load, refreshKey]);

  // 自适应轮询：有在跑的任务就快刷新（看清 last_page 推进），否则慢刷新兜底。
  const hasActive = jobs.some(isActive);
  React.useEffect(() => {
    const interval = hasActive ? ACTIVE_POLL_MS : IDLE_POLL_MS;
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load({ silent: true });
    }, interval);
    const onVisible = () => {
      if (document.visibilityState === "visible") void load({ silent: true });
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [hasActive, load]);

  // 撤销一条待采集任务：409 说明已被 worker 认领，提示"已开始，不能撤销"。
  const cancelJob = async (id: number) => {
    setCancelling(id);
    try {
      await vuln.shodanCollectCancel(id);
      toast.success(`已撤销任务 #${id}`);
      await load({ silent: true });
    } catch (e) {
      toast.error(`撤销失败：${String((e as Error)?.message ?? e)}`);
    } finally {
      setCancelling(null);
    }
  };

  const applyFilters = () => {
    setPage(0);
    setApplied({
      status: status === "all" ? undefined : status,
      cve_id: cveId.trim() || undefined,
      q: query.trim() || undefined,
    });
  };

  const counts = React.useMemo(() => {
    const acc: Record<string, number> = {};
    for (const j of jobs) acc[j.status] = (acc[j.status] ?? 0) + 1;
    return acc;
  }, [jobs]);

  const runningCount = jobs.filter((j) => j.status === "running").length;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      {/* 工具条：横向排一行，窄屏自动换行。不用 FieldGroup（默认 flex-col，会把
          筛选器堆成右侧一竖溜）。 */}
      <Card className="flex-row flex-wrap items-end gap-3 p-3">
        <div className="flex w-40 shrink-0 flex-col gap-1">
          <FieldLabel htmlFor="cj-status">状态</FieldLabel>
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger id="cj-status" className="h-8">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex w-56 shrink-0 flex-col gap-1">
          <FieldLabel htmlFor="cj-cve">关联 CVE</FieldLabel>
          <Input
            id="cj-cve"
            className="h-8"
            placeholder="如 CVE-2019-17558"
            value={cveId}
            onChange={(e) => setCveId(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") applyFilters();
            }}
          />
        </div>
        <div className="flex w-64 shrink-0 flex-col gap-1">
          <FieldLabel htmlFor="cj-query">查询语句</FieldLabel>
          <Input
            id="cj-query"
            className="h-8"
            placeholder="按 query 子串搜索"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") applyFilters();
            }}
          />
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={applyFilters}>
            <SearchIcon className="size-3.5" /> 筛选
          </Button>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            <RefreshCwIcon className="size-3.5" /> 刷新
          </Button>
        </div>
        <div className="text-muted-foreground ml-auto flex items-center gap-3 text-xs">
          <span>
            本页 {jobs.length} / 共 {total} 条
          </span>
          {runningCount > 0 ? (
            <span className="text-sky-600 dark:text-sky-400">{runningCount} 条采集中</span>
          ) : null}
          {counts.done ? <span>本页已完成 {counts.done}</span> : null}
          {counts.failed ? <span className="text-rose-600 dark:text-rose-400">本页失败 {counts.failed}</span> : null}
        </div>
      </Card>

      {error ? (
        <Card
          role="alert"
          className="border-rose-500/40 p-3 text-sm text-rose-600 dark:text-rose-400"
        >
          列表加载失败：{error}
        </Card>
      ) : null}

      <Card className="min-h-0 flex-1 overflow-auto p-0" aria-busy={loading}>
        <Table>
          <TableHeader className="bg-muted/40 sticky top-0 z-10">
            <TableRow>
              <TableHead className="w-16">任务</TableHead>
              <TableHead className="min-w-[220px]">查询语句</TableHead>
              <TableHead className="w-36">关联 CVE</TableHead>
              <TableHead className="w-24">状态</TableHead>
              <TableHead className="w-40">进度</TableHead>
              <TableHead className="w-20 text-right">资产</TableHead>
              <TableHead className="w-20 text-right">额度</TableHead>
              <TableHead className="w-24">发起人</TableHead>
              <TableHead className="w-28">更新时间</TableHead>
              <TableHead className="min-w-[160px]">备注 / 失败原因</TableHead>
              <TableHead className="w-20">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {jobs.length === 0 && !loading ? (
              <TableRow>
                <TableCell colSpan={11} className="text-muted-foreground h-24 text-center text-sm">
                  还没有采集任务。到 CVE 列表点「采集」后，这里会实时显示进度。
                </TableCell>
              </TableRow>
            ) : null}
            {jobs.map((job) => {
              const pct =
                job.max_pages > 0 ? Math.min(100, Math.round((job.last_page / job.max_pages) * 100)) : 0;
              return (
                <TableRow key={job.id}>
                  <TableCell className="font-mono text-xs">#{job.id}</TableCell>
                  <TableCell className="font-mono text-xs break-all">{job.query}</TableCell>
                  <TableCell>
                    {job.cve_id ? (
                      <Link
                        href={`/vuln/assets?cve=${encodeURIComponent(job.cve_id)}`}
                        className="text-primary inline-flex items-center gap-1 font-mono text-xs hover:underline"
                      >
                        {job.cve_id}
                        <ExternalLinkIcon className="size-3" />
                      </Link>
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={job.status} />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Progress
                        value={pct}
                        className="h-1.5 w-20"
                        aria-label={`任务 #${job.id} 采集进度 ${job.last_page}/${job.max_pages} 页`}
                      />
                      <span className="text-muted-foreground font-mono text-[11px] tabular-nums">
                        {job.last_page}/{job.max_pages}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs tabular-nums">
                    {job.assets_written ?? 0}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs tabular-nums">
                    {job.credits_spent ?? 0}
                  </TableCell>
                  <TableCell className="text-muted-foreground truncate text-xs">{job.created_by || "—"}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">{fmtTime(job.updated_at)}</TableCell>
                  <TableCell className="text-xs">
                    {job.note ? (
                      <span className={job.status === "failed" ? "text-rose-600 dark:text-rose-400" : ""}>
                        {job.note}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {job.status === "pending" ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-muted-foreground hover:text-rose-600 h-7 px-2 text-xs"
                        disabled={cancelling === job.id}
                        aria-label={`撤销任务 #${job.id}`}
                        onClick={() => void cancelJob(job.id)}
                      >
                        {cancelling === job.id ? "撤销中…" : "撤销"}
                      </Button>
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Card>

      <div className="flex items-center justify-between">
        <span className="text-muted-foreground text-xs">
          {hasActive ? "有任务进行中，每 2 秒自动刷新" : "全部任务已结束，每 10 秒兜底刷新"}
        </span>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={page === 0 || loading}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            上一页
          </Button>
          <span className="text-muted-foreground text-xs tabular-nums">
            第 {page + 1} / {Math.max(1, Math.ceil(total / PAGE_SIZE))} 页
          </span>
          <Button
            size="sm"
            variant="outline"
            disabled={loading || (page + 1) * PAGE_SIZE >= total}
            onClick={() => setPage((p) => p + 1)}
          >
            下一页
          </Button>
        </div>
      </div>
    </div>
  );
}

// VulnCollectJobsForCve 是 CVE 详情里的「该 CVE 的采集任务」区块（kt-vuln#73 验收：
// CVE → 采集任务 → 写入资产 要形成闭环）。只依赖 ARTEX 自己的
// /api/vuln/shodan-collect/jobs?cve_id=…，不经过 kt-vuln 代理，所以本地也能验。
export function VulnCollectJobsForCve({ cveId, limit = 5 }: { cveId: string; limit?: number }) {
  const isAdmin = useIsAdmin();
  const [jobs, setJobs] = React.useState<VulnCollectJob[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    if (!isAdmin) return;
    const controller = new AbortController();
    setLoading(true);
    vuln
      .shodanCollectJobs({ cve_id: cveId, limit }, { signal: controller.signal })
      .then((r) => {
        if (controller.signal.aborted) return;
        setJobs(r.items);
        setError("");
      })
      .catch((e) => {
        if (controller.signal.aborted) return;
        // 未配置采集器等后端错误降级成一句提示，不影响 CVE 详情本身。
        setError(String((e as Error)?.message ?? e));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => {
      controller.abort();
    };
  }, [cveId, limit, isAdmin]);

  // 采集接口是 admin 门：非管理员不渲染、也不发请求（隐藏不替代后端 403）。
  if (!isAdmin) return null;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">采集任务</span>
        <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" asChild>
          <Link href={`/vuln/collect-jobs?cve=${encodeURIComponent(cveId)}`}>全部任务</Link>
        </Button>
      </div>
      {loading ? (
        <p role="status" className="text-muted-foreground text-xs">
          加载中…
        </p>
      ) : error ? (
        <p role="alert" className="text-muted-foreground text-xs">
          任务读取失败：{error}
        </p>
      ) : jobs.length === 0 ? (
        <p className="text-muted-foreground text-xs">该 CVE 还没有发起过采集。</p>
      ) : (
        <div className="flex flex-col gap-1">
          {jobs.map((job) => (
            <div
              key={job.id}
              className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border px-2 py-1.5 text-xs"
            >
              <span className="font-mono">#{job.id}</span>
              <StatusBadge status={job.status} />
              <span className="text-muted-foreground font-mono tabular-nums">
                {job.last_page}/{job.max_pages}
              </span>
              <span className="text-muted-foreground">资产 {job.assets_written ?? 0}</span>
              <span className="text-muted-foreground">额度 {job.credits_spent ?? 0}</span>
              <span className="font-mono break-all">{job.query}</span>
              {job.note && job.status === "failed" ? (
                <span className="text-rose-600 dark:text-rose-400">{job.note}</span>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
