// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { VulnCollectJob } from "@/lib/vuln";

import { VulnCollectJobsForCve, VulnCollectJobsPanel } from "./panels-jobs";

const { jobsMock, cancelMock, toastErrorMock, admin } = vi.hoisted(() => ({
  jobsMock: vi.fn(),
  cancelMock: vi.fn(),
  toastErrorMock: vi.fn(),
  admin: { value: true },
}));

vi.mock("@/hooks/use-is-admin", () => ({ useIsAdmin: () => admin.value }));
vi.mock("@/lib/vuln", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/vuln")>();
  return {
    ...actual,
    vuln: { ...actual.vuln, shodanCollectJobs: jobsMock, shodanCollectCancel: cancelMock },
  };
});
vi.mock("sonner", () => ({ toast: { error: toastErrorMock, success: vi.fn(), info: vi.fn() } }));

function job(overrides: Partial<VulnCollectJob> = {}): VulnCollectJob {
  return {
    id: 16,
    query: 'product:"Apache Solr"',
    max_pages: 5,
    status: "pending",
    last_page: 0,
    credits_spent: 0,
    assets_written: 0,
    cve_id: "CVE-2019-17558",
    created_by: "artex-web",
    updated_at: "2026-11-07T04:00:00Z",
    ...overrides,
  };
}

describe("VulnCollectJobsForCve", () => {
  beforeEach(() => {
    jobsMock.mockReset();
    admin.value = true;
  });

  afterEach(cleanup);

  it("非管理员不请求任务接口，也不渲染入口", () => {
    admin.value = false;
    const { container } = render(<VulnCollectJobsForCve cveId="CVE-2019-17558" />);
    expect(container.textContent).toBe("");
    expect(jobsMock).not.toHaveBeenCalled();
  });

  it("管理员看到该 CVE 的任务摘要与深链", async () => {
    jobsMock.mockResolvedValue({ items: [job()], total: 1 });
    render(<VulnCollectJobsForCve cveId="CVE-2019-17558" />);

    expect(await screen.findByText("#16")).toBeTruthy();
    expect(screen.getByText("待采集")).toBeTruthy();
    expect(screen.getByRole("link", { name: "全部任务" }).getAttribute("href")).toBe(
      "/vuln/collect-jobs?cve=CVE-2019-17558",
    );
    expect(jobsMock).toHaveBeenCalledWith(
      { cve_id: "CVE-2019-17558", limit: 5 },
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });
});

describe("VulnCollectJobsPanel", () => {
  beforeEach(() => {
    jobsMock.mockReset();
    cancelMock.mockReset();
    toastErrorMock.mockReset();
    admin.value = true;
    jobsMock.mockResolvedValue({ items: [job()], total: 1 });
  });

  afterEach(cleanup);

  it("撤销被 worker 认领的任务时展示后端 409 文案", async () => {
    cancelMock.mockRejectedValue(new Error("任务已开始或已结束，不能撤销"));
    render(<VulnCollectJobsPanel refreshKey={0} />);

    fireEvent.click(await screen.findByRole("button", { name: "撤销任务 #16" }));

    await waitFor(() =>
      expect(toastErrorMock).toHaveBeenCalledWith("撤销失败：任务已开始或已结束，不能撤销"),
    );
    expect(cancelMock).toHaveBeenCalledWith(16);
  });

  it("筛选参数来自用户输入时只做 trim，不拼 URL", async () => {
    render(<VulnCollectJobsPanel refreshKey={0} />);
    await screen.findByText("#16");

    fireEvent.change(screen.getByLabelText("关联 CVE"), { target: { value: "  CVE-2021-44228  " } });
    fireEvent.click(screen.getByRole("button", { name: "筛选" }));

    await waitFor(() =>
      expect(jobsMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ cve_id: "CVE-2021-44228", limit: 50, offset: 0 }),
        expect.anything(),
      ),
    );
  });
});
