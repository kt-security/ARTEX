// Shodan 查询体质量判定与精准指纹推荐（kt-vuln#73 采集质量问题 1/2）。
//
// 背景（实测）：裸关键词 `solr` + `country:US` 采回 500 条资产，抽查 0 条是 Solr——
// Shodan 的裸关键词会命中 banner/页面文本/CSP 头里的任意 "solr"；而
// `http.title:"Solr Admin"` 命中 2,577 条且抽样全真。同理 `port:8983` 这类纯端口
// 过滤捞到的是 RDP/LuCI/Teleport，真实 Solr 分布在 8467/14894 这种随机端口上。
//
// 本模块只做两件事，都是纯函数、无副作用（面板与弹窗共用）：
//   1. analyzeCollectQuery：判定查询体属于「精准指纹 / 只有范围条件 / 裸关键词」，
//      给出给用户看的风险文案；
//   2. collectQuerySuggestions：按 CVE 的 known 组件，生成推荐查询体供一键填入。

/** 能识别"这个服务是什么"的过滤条件：有它就够精准。 */
const IDENTIFIER_FILTERS = [
  "product",
  "http.title",
  "http.html",
  "http.favicon.hash",
  "icon.hash",
  "http.component",
  "vuln",
  "cpe",
  "hash",
  "ssl.cert.subject",
] as const;

/** 只缩范围、不识别身份的过滤条件（country/org/port…）。 */
const SCOPE_FILTERS = [
  "country",
  "city",
  "region",
  "org",
  "asn",
  "net",
  "port",
  "geo",
  "before",
  "after",
] as const;

export type CollectQueryLevel = "precise" | "scoped" | "bare";

export interface CollectQueryAnalysis {
  /** precise=含识别型 filter；scoped=只有国家/端口这类范围条件；bare=裸关键词。 */
  level: CollectQueryLevel;
  /** 是否含识别型 filter。 */
  hasIdentifier: boolean;
  /** 唯一的 filter 是 port:（issue 问题 2 的典型反例）。 */
  onlyPort: boolean;
  /** 是否完全没有任何 filter（issue 问题 1 的典型反例）。 */
  bare: boolean;
  /** 给用户看的一句话结论；precise 时为 undefined。 */
  warning?: string;
}

/** 抽出查询体里的 filter 名（`product:"x"` → product），识别 `k:v` 与 `k="v"` 两种写法。 */
export function extractFilters(query: string): string[] {
  // 先剥掉引号内的字面量，避免 `http.title:"Druid: Console"` 把标题里的词当 filter。
  const unquoted = query.replace(/"[^"]*"/g, '""');
  const found = new Set<string>();
  for (const m of unquoted.matchAll(/([a-z][a-z0-9_.]*)\s*(?::|=)/gi)) {
    found.add(m[1].toLowerCase());
  }
  return [...found];
}

/**
 * 判定查询体精度。
 *
 * 判定顺序：有识别型 filter → precise；否则有 port 且无其它 → scoped(onlyPort)；
 * 只有国家/org 等 → scoped；一个 filter 都没有 → bare。
 */
export function analyzeCollectQuery(query: string): CollectQueryAnalysis {
  const trimmed = query.trim();
  if (trimmed === "") {
    return { level: "bare", hasIdentifier: false, onlyPort: false, bare: true };
  }
  const filters = extractFilters(trimmed);
  const hasIdentifier = filters.some((f) => IDENTIFIER_FILTERS.some((idf) => f === idf || f.startsWith(`${idf}.`)));
  if (hasIdentifier) {
    return { level: "precise", hasIdentifier: true, onlyPort: false, bare: false };
  }
  const scopeOnly = filters.filter((f) => SCOPE_FILTERS.some((s) => f === s || f.startsWith(`${s}.`)));
  const onlyPort = filters.length > 0 && filters.every((f) => f === "port");
  if (filters.length === 0) {
    return {
      level: "bare",
      hasIdentifier: false,
      onlyPort: false,
      bare: true,
      warning:
        "查询里没有任何 filter（裸关键词）：Shodan 会匹配 banner/页面文本里的任意提及，" +
        "实测 500 条 0 条命中。建议改用 product: / http.title: 精准指纹。",
    };
  }
  if (onlyPort) {
    return {
      level: "scoped",
      hasIdentifier: false,
      onlyPort: true,
      bare: false,
      warning:
        "只用端口过滤：端口上跑的是什么都可能（实测 port:8983 捞到 RDP/LuCI/Teleport），" +
        "且真实服务常跑随机端口。端口只能叠加在 product: / http.title: 之上。",
    };
  }
  return {
    level: "scoped",
    hasIdentifier: false,
    onlyPort: false,
    bare: false,
    warning: `当前只有范围条件（${scopeOnly.join("、") || "过滤项"}），没有识别服务身份的过滤条件，预计精度很低。`,
  };
}

/** 从 CVE 元数据里能提取出的「组件名」候选（去重、去空）。 */
export function collectSubjectCandidates(input: {
  product?: string | null;
  vendor?: string | null;
  title?: string | null;
  affected?: Record<string, string[]> | null;
}): string[] {
  const out: string[] = [];
  const push = (v?: string | null) => {
    const s = (v ?? "").trim();
    if (!s || s.length > 40) return;
    if (!out.some((x) => x.toLowerCase() === s.toLowerCase())) out.push(s);
  };
  push(input.product);
  for (const key of Object.keys(input.affected ?? {})) push(key);
  return out.slice(0, 3);
}

export interface CollectQuerySuggestion {
  /** 展示用的短标签。 */
  label: string;
  /** 点一下就填进输入框的查询体。 */
  query: string;
  /** 一句话说明这条件有多准。 */
  hint: string;
}

/**
 * 生成推荐查询体：识别型 filter 优先（product / http.title），范围条件由用户自己叠。
 * 没有可用组件时返回空数组——弹窗会退化为「只有自由输入 + 低精度提示」。
 */
export function collectQuerySuggestions(input: {
  product?: string | null;
  vendor?: string | null;
  title?: string | null;
  affected?: Record<string, string[]> | null;
}): CollectQuerySuggestion[] {
  const subjects = collectSubjectCandidates(input);
  const out: CollectQuerySuggestion[] = [];
  for (const subject of subjects) {
    out.push({
      label: `product:"${subject}"`,
      query: `product:"${subject}"`,
      hint: "按 Shodan 产品指纹匹配，精度高",
    });
  }
  // 管理台类服务用标题指纹更准（Solr Admin / Druid / Kibana…），只对第一个组件加一条。
  const first = subjects[0];
  if (first) {
    const words = first.replace(/[-_]+/g, " ").trim();
    out.push({
      label: `http.title:"${words}"`,
      query: `http.title:"${words}"`,
      hint: "按页面标题匹配，管理台类服务最准",
    });
  }
  return out;
}
