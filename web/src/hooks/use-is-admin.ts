"use client";

import { useEffect, useState } from "react";

import { auth } from "@/lib/auth";

/**
 * 当前会话是否具备 admin 角色。
 *
 * 返回 null 表示尚未完成 hydration（此时不要渲染受权限控制的内容，避免
 * 先闪一下「无权限」）；前端显隐只是 UX，真正的权限仍由后端 requireRole 兜底。
 */
export function useIsAdmin(): boolean | null {
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);

  useEffect(() => {
    setIsAdmin(auth.getRoles().includes("admin"));
  }, []);

  return isAdmin;
}
