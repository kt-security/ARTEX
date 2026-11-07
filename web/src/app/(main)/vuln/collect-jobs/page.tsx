"use client";

// Vuln 情报站 · 采集任务（kt-vuln#73）。
// 提交采集后不再"凭空消失"：任务列表能看到状态、页数进度、写入资产、消耗额度与
// 失败原因；按 CVE 过滤即可从 CVE 维度回溯它发起过哪些采集。
// 与 /vuln/assets 的下钻约定一致：支持 ?cve=CVE-YYYY-NNNN 直接进入该 CVE 的任务视图。

import * as React from "react";

import { RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";

import { VulnCollectJobsPanel } from "../_components/panels-jobs";

function VulnCollectJobsContent() {
  const [refreshKey, setRefreshKey] = React.useState(0);
  // 支持从 CVE 详情/任务行直接跳到「该 CVE 的采集任务」（与 /vuln/assets?cve= 同一约定）。
  const [cve, setCve] = React.useState<string | undefined>(undefined);

  React.useEffect(() => {
    const value = new URLSearchParams(window.location.search).get("cve");
    setCve(value?.trim() ? value.trim() : undefined);
  }, []);

  return (
    <div className="flex h-[calc(100vh-6rem)] min-h-0 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">采集任务</h1>
          <p className="text-sm text-muted-foreground">
            Shodan 采集队列 · 每页 1 credit、100 条 · 同查询的未完成任务幂等合并
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setRefreshKey((k) => k + 1)}>
          <RefreshCwIcon className="size-4" /> 刷新
        </Button>
      </div>
      <VulnCollectJobsPanel refreshKey={refreshKey} initialCve={cve} />
    </div>
  );
}

export default function VulnCollectJobsPage() {
  return <VulnCollectJobsContent />;
}
