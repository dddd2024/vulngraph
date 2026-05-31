(function () {
  "use strict";

  const els = {
    topStatus: document.getElementById("topStatus"),
    topEngine: document.getElementById("topEngine"),
    topJob: document.getElementById("topJob"),
    langSwitch: document.getElementById("langSwitch"),
    kpiFindings: document.getElementById("kpiFindings"),
    kpiMaxRisk: document.getElementById("kpiMaxRisk"),
    kpiCritical: document.getElementById("kpiCritical"),
    kpiEngine: document.getElementById("kpiEngine"),
    kpiSkipped: document.getElementById("kpiSkipped"),
    segCode: document.getElementById("segCode"),
    segGithub: document.getElementById("segGithub"),
    codePanel: document.getElementById("codePanel"),
    repoPanel: document.getElementById("repoPanel"),
    codeInput: document.getElementById("codeInput"),
    languageSelect: document.getElementById("languageSelect"),
    repoUrl: document.getElementById("repoUrl"),
    analyzeInputBtn: document.getElementById("analyzeInputBtn"),
    resetBtn: document.getElementById("resetBtn"),
    testsBtn: document.getElementById("testsBtn"),
    progressBar: document.getElementById("progressBar"),
    jobInfo: document.getElementById("jobInfo"),
    errorPanel: document.getElementById("errorPanel"),
    findingsList: document.getElementById("findingsList"),
    findingsEmpty: document.getElementById("findingsEmpty"),
    findingDetail: document.getElementById("findingDetail"),
    graphBtn: document.getElementById("graphBtn"),
    kgBtn: document.getElementById("kgBtn"),
    kgAiMode: document.getElementById("kgAiMode"),
    kgModelName: document.getElementById("kgModelName"),
    kgApiKey: document.getElementById("kgApiKey"),
    kgSyncNeo4j: document.getElementById("kgSyncNeo4j"),
    graphOut: document.getElementById("graphOut"),
    rawOut: document.getElementById("rawOut"),
    copyJsonBtn: document.getElementById("copyJsonBtn")
  };

  let inputType = "code";
  let lastAnalysisResult = null;
  let sortedFindings = [];
  let selectedIndex = -1;
  let running = false;
  let currentLang = "zh-CN";
  let activeLangFilter = "all";
  const I18N = {
    "zh-CN": {
      productSub: "基于多语言静态分析与知识图谱的漏洞检测系统",
      service: "服务", engine: "引擎", job: "任务",
      navAnalyze: "分析", navFindings: "漏洞", navGraph: "图谱", navRaw: "原始 JSON",
      titleOverview: "安全总览", titleAnalyze: "分析目标", titleProgress: "分析进度",
      titleFindings: "漏洞发现", titleDetail: "漏洞详情", titleAdvanced: "高级分析", titleRaw: "高级原始 JSON",
      kpiFindings: "漏洞数量", kpiMaxRisk: "最大风险", kpiCritical: "高危问题", kpiEngine: "多引擎检测", kpiSkipped: "跳过文件",
      segCode: "代码片段", segGithub: "GitHub 仓库",
      analyzeBtn: "开始分析", resetBtn: "重置演示项目", testsBtn: "运行检测回归测试",
      copyJson: "复制 JSON",
      stepPrepare: "准备", stepDetect: "检测", stepReport: "报告", stepDone: "完成",
      ready: "就绪", none: "无", online: "在线", offline: "离线", idle: "空闲",
      engineDisplay: "多引擎检测",
      kgAiMode: "知识图谱 AI 模式", kgModelName: "模型名称（可选）", kgApiKey: "API Key（可选）",
      kgSyncNeo4j: "同步到 Neo4j",
      phModelName: "留空使用默认模型", phApiKey: "留空使用 .env 配置"
    },
    "en-US": {
      productSub: "Multi-Language Static Analysis and Knowledge Graph Based Vulnerability Detection",
      service: "Service", engine: "Engine", job: "Job",
      navAnalyze: "Analyze", navFindings: "Findings", navGraph: "Graph", navRaw: "Raw JSON",
      titleOverview: "Security Overview", titleAnalyze: "Analyze Target", titleProgress: "Analysis Progress",
      titleFindings: "Findings", titleDetail: "Finding Detail", titleAdvanced: "Advanced Analysis", titleRaw: "Advanced Raw JSON",
      kpiFindings: "Findings", kpiMaxRisk: "Max Risk", kpiCritical: "Critical Issues", kpiEngine: "Multi-engine Detection", kpiSkipped: "Skipped Files",
      segCode: "Code Snippet", segGithub: "GitHub Repository",
      analyzeBtn: "Start Analyze", resetBtn: "Reset Demo", testsBtn: "Run Detection Regression Tests",
      copyJson: "Copy JSON",
      stepPrepare: "Prepare", stepDetect: "Detect", stepReport: "Report", stepDone: "Done",
      ready: "ready", none: "none", online: "online", offline: "offline", idle: "idle",
      engineDisplay: "Multi-engine Detection",
      kgAiMode: "Knowledge Graph AI Mode", kgModelName: "Model Name (optional)", kgApiKey: "API Key (optional)",
      kgSyncNeo4j: "Sync to Neo4j",
      phModelName: "Leave blank to use default model", phApiKey: "Leave blank to use .env config"
    }
  };
  function t(k) { return (I18N[currentLang] && I18N[currentLang][k]) || k; }

  function setInputType(nextType) {
    inputType = nextType;
    const code = nextType === "code";
    els.segCode.classList.toggle("active", code);
    els.segGithub.classList.toggle("active", !code);
    els.codePanel.classList.toggle("hidden", !code);
    els.repoPanel.classList.toggle("hidden", code);
  }

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async function call(url, method = "GET", body = null) {
    const resp = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : null
    });
    const text = await resp.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    if (!resp.ok) throw new Error(data.detail || data.raw || ("HTTP " + resp.status));
    return data;
  }

  function setRunning(nextRunning) {
    running = nextRunning;
    els.analyzeInputBtn.disabled = nextRunning;
  }

  function setTopbarState(jobText) {
    els.topEngine.textContent = t("engineDisplay");
    if (jobText) els.topJob.textContent = jobText === "idle" ? t("idle") : jobText;
  }

  function riskClass(score) {
    const n = Number(score) || 0;
    if (n >= 80) return "high";
    if (n >= 50) return "mid";
    if (n >= 1) return "low";
    return "zero";
  }

  function maxRiskClass(score) {
    const n = Number(score) || 0;
    if (n >= 80) return "risk-high";
    if (n >= 50) return "risk-mid";
    if (n >= 1) return "risk-low";
    return "risk-zero";
  }

  function setError(message) {
    const text = String(message || "").trim();
    if (!text) {
      els.errorPanel.classList.add("hidden");
      els.errorPanel.textContent = "";
      return;
    }
    els.errorPanel.classList.remove("hidden");
    els.errorPanel.textContent = text;
  }

  function stageToStep(stageText, status, progress) {
    const stage = String(stageText || "").toLowerCase();
    if (status === "completed") return "done";
    if (stage.includes("report")) return "report";
    if (stage.includes("detect") || stage.includes("analysis") || stage.includes("scan")) return "detect";
    if ((Number(progress) || 0) > 70) return "report";
    if ((Number(progress) || 0) > 20) return "detect";
    return "prepare";
  }

  function updateStepper(activeStep) {
    const order = ["prepare", "detect", "report", "done"];
    const activeIndex = order.indexOf(activeStep);
    const nodes = document.querySelectorAll(".step");
    nodes.forEach((node) => {
      const i = order.indexOf(node.dataset.step);
      node.classList.remove("active", "done");
      if (i < activeIndex) node.classList.add("done");
      if (i === activeIndex) node.classList.add("active");
      if (activeStep === "done" && i <= activeIndex) node.classList.add("done");
    });
  }

  function setJobProgress(job) {
    const status = String(job.status || "idle");
    const stage = String(job.stage || "-");
    const progress = Math.max(0, Math.min(100, Number(job.progress) || 0));
    const message = String(job.message || "");
    const step = stageToStep(stage, status, progress);
    updateStepper(step);
    els.progressBar.style.width = progress + "%";
    if (currentLang === "zh-CN") {
      els.jobInfo.textContent = "状态：" + status + " · 阶段：" + stage + " · 进度：" + progress + "% · " + message;
    } else {
      els.jobInfo.textContent = "Status: " + status + " · Stage: " + stage + " · Progress: " + progress + "% · " + message;
    }
    els.topJob.textContent = status;
  }

  function severityLabel(v) {
    const s = String(v || "").toUpperCase();
    if (s === "ERROR") return "严重";
    if (s === "WARN" || s === "WARNING") return "警告";
    if (s === "INFO") return "信息";
    return s || "未知";
  }

  function confidenceLabel(v) {
    const s = String(v || "").toLowerCase();
    if (s === "high") return "高";
    if (s === "medium") return "中";
    if (s === "low") return "低";
    return s || "-";
  }

  function engineLabels(arr) {
    return (Array.isArray(arr) ? arr : []).map((x) => {
      if (x === "ast") return "AST";
      if (x === "pattern") return "Pattern";
      return x;
    });
  }

  function renderFindings(result) {
    const vulns = Array.isArray(result && result.findings) ? result.findings.slice() : [];
    vulns.sort((a, b) => (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0));
    sortedFindings = vulns;
    els.findingsList.innerHTML = "";

    // 语言汇总
    renderLangSummary(vulns);

    // 语言过滤
    const filtered = activeLangFilter === "all"
      ? vulns
      : vulns.filter(v => (v.language || "Python") === activeLangFilter);

    if (filtered.length === 0) {
      selectedIndex = -1;
      els.findingsEmpty.classList.remove("hidden");
      els.findingDetail.textContent = "未发现漏洞。";
      return;
    }

    els.findingsEmpty.classList.add("hidden");
    filtered.forEach((item, idx) => {
      const risk = Number(item.risk_score) || 0;
      const lang = item.language || "Python";
      const row = document.createElement("button");
      row.type = "button";
      row.className = "finding-item";
      row.innerHTML =
        '<div class="finding-title">' + (item.type || "Unknown") + '</div>' +
        '<div class="finding-meta">' +
        '<span class="badge ' + riskClass(risk) + '">Risk ' + risk + "</span>" +
        '<span class="lang-badge">' + escapeHtml(lang) + '</span>' +
        '<span>' + severityLabel(item.severity) + "</span> · " +
        '<span>' + (item.file || "-") + ":" + (item.line || 0) + "</span>" +
        "</div>";
      row.addEventListener("click", () => selectFinding(idx, filtered));
      els.findingsList.appendChild(row);
    });

    selectFinding(0, filtered);
  }

  function renderLangSummary(vulns) {
    const langCounts = {};
    (vulns || []).forEach(v => {
      const lang = v.language || "Python";
      langCounts[lang] = (langCounts[lang] || 0) + 1;
    });
    const langSummaryEl = document.getElementById("langSummary");
    if (!langSummaryEl) return;
    const entries = Object.entries(langCounts).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) {
      langSummaryEl.innerHTML = "";
      return;
    }
    langSummaryEl.innerHTML = entries.map(([lang, count]) =>
      '<span class="lang-summary-item"><strong>' + escapeHtml(lang) + '</strong>: ' + count + '</span>'
    ).join("");
  }

  function renderDetail(item) {
    if (!item) {
      els.findingDetail.textContent = "请选择一条漏洞记录查看详情。";
      return;
    }
    const engines = engineLabels(item.engines).join(", ") || "-";
    const lang = item.language || "Python";
    els.findingDetail.innerHTML =
      '<div class="detail-grid">' +
      '<div class="k">严重级别</div><div class="v">' + severityLabel(item.severity) + "</div>" +
      '<div class="k">漏洞类型</div><div class="v">' + (item.type || "-") + "</div>" +
      '<div class="k">语言</div><div class="v">' + escapeHtml(lang) + "</div>" +
      '<div class="k">CWE</div><div class="v">' + (item.cwe || "-") + "</div>" +
      '<div class="k">风险分</div><div class="v">' + (item.risk_score ?? "-") + "</div>" +
      '<div class="k">置信度</div><div class="v">' + confidenceLabel(item.confidence) + "</div>" +
      '<div class="k">位置</div><div class="v">' + (item.file || "-") + ":" + (item.line || 0) + "</div>" +
      '<div class="k">检测引擎</div><div class="v">' + engines + "</div>" +
      "</div>";
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function escapeAttr(s) {
    return escapeHtml(s)
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function selectFinding(idx, filtered) {
    selectedIndex = idx;
    const items = filtered || sortedFindings;
    const nodes = els.findingsList.querySelectorAll(".finding-item");
    nodes.forEach((node, i) => node.classList.toggle("active", i === idx));
    const item = items[idx];
    renderDetail(item);
  }

  function updateOverview(result) {
    const vulns = Array.isArray(result && result.findings) ? result.findings : [];
    const risks = vulns.map(v => Number(v.risk_score) || 0);
    const maxRisk = risks.length ? Math.max.apply(null, risks) : 0;
    const critical = vulns.filter(v => (Number(v.risk_score) || 0) >= 80).length;
    const skipped = Array.isArray(result && result.skipped_details)
      ? result.skipped_details.length
      : (Array.isArray(result && result.skipped_files) ? result.skipped_files.length : 0);

    els.kpiFindings.textContent = String(vulns.length);
    els.kpiMaxRisk.textContent = String(maxRisk);
    els.kpiMaxRisk.classList.remove("risk-high", "risk-mid", "risk-low", "risk-zero");
    els.kpiMaxRisk.classList.add(maxRiskClass(maxRisk));
    els.kpiCritical.textContent = String(critical);
    els.kpiEngine.textContent = t("engineDisplay");
    els.kpiSkipped.textContent = String(skipped);
  }

  function setRawJson(data) {
    els.rawOut.textContent = JSON.stringify(data, null, 2);
  }

  function renderCallGraph(data) {
    const edges = Array.isArray(data && data.edges) ? data.edges : [];
    if (edges.length === 0) {
      els.graphOut.innerHTML = '<div class="empty">未发现函数调用关系</div>';
      return;
    }

    const functions = new Set();
    const inDegree = new Map();
    const outDegree = new Map();
    edges.forEach((edge) => {
      const source = String(edge.source || "").trim();
      const target = String(edge.target || "").trim();
      if (!source || !target) return;
      functions.add(source);
      functions.add(target);
      outDegree.set(source, (outDegree.get(source) || 0) + 1);
      inDegree.set(target, (inDegree.get(target) || 0) + 1);
      if (!inDegree.has(source)) inDegree.set(source, inDegree.get(source) || 0);
      if (!outDegree.has(target)) outDegree.set(target, outDegree.get(target) || 0);
    });

    const functionList = Array.from(functions).sort();
    const entryCandidates = functionList
      .filter((name) => (inDegree.get(name) || 0) === 0 && (outDegree.get(name) || 0) > 0)
      .sort((a, b) => (outDegree.get(b) || 0) - (outDegree.get(a) || 0) || a.localeCompare(b));
    const topCalled = functionList
      .filter((name) => (inDegree.get(name) || 0) > 0)
      .sort((a, b) => (inDegree.get(b) || 0) - (inDegree.get(a) || 0) || a.localeCompare(b))
      .slice(0, 8);
    const maxCalled = topCalled.length ? topCalled[0] : "无";

    const chipHtml = (items, countMap, emptyText) => {
      if (!items.length) return '<span class="muted">' + emptyText + "</span>";
      return items.slice(0, 8).map((name) => {
        const count = countMap ? (countMap.get(name) || 0) : 0;
        const suffix = count ? " · " + count : "";
        return '<span class="chip">' + escapeHtml(name) + escapeHtml(suffix) + "</span>";
      }).join("");
    };

    const rows = edges.map((edge, idx) => {
      const source = String(edge.source || "");
      const target = String(edge.target || "");
      return (
        "<tr>" +
        "<td>" + String(idx + 1) + "</td>" +
        "<td>" + escapeHtml(source) + "</td>" +
        "<td>" + escapeHtml(target) + "</td>" +
        "</tr>"
      );
    }).join("");

    els.graphOut.innerHTML =
      '<div class="graph-summary-grid">' +
      '<div class="mini-kpi"><div class="kpi-label">函数数量</div><div class="kpi-value">' + functionList.length + "</div></div>" +
      '<div class="mini-kpi"><div class="kpi-label">调用关系</div><div class="kpi-value">' + edges.length + "</div></div>" +
      '<div class="mini-kpi"><div class="kpi-label">入口候选</div><div class="kpi-value">' + entryCandidates.length + "</div></div>" +
      '<div class="mini-kpi"><div class="kpi-label">被调用最多</div><div class="kpi-value">' + escapeHtml(maxCalled) + "</div></div>" +
      "</div>" +
      '<div class="chip-row"><strong>入口候选函数</strong>' + chipHtml(entryCandidates, outDegree, "无") + "</div>" +
      '<div class="chip-row"><strong>热门被调用函数</strong>' + chipHtml(topCalled, inDegree, "无") + "</div>" +
      '<div class="graph-table-wrap">' +
      '<table class="graph-table">' +
      "<thead><tr><th>#</th><th>调用方</th><th>被调用方</th></tr></thead>" +
      "<tbody>" + rows + "</tbody>" +
      "</table>" +
      "</div>";
  }

  function renderKnowledgeGraph(data) {
    const nodes = Array.isArray(data && data.nodes) ? data.nodes : [];
    const edges = Array.isArray(data && data.edges) ? data.edges : [];
    const summary = data && data.summary ? data.summary : {};
    if (nodes.length === 0) {
      els.graphOut.innerHTML = '<div class="empty">暂无漏洞知识图谱数据</div>';
      return;
    }

    const nodeById = new Map();
    nodes.forEach((node) => nodeById.set(String(node.id || ""), node));

    const outgoing = new Map();
    edges.forEach((edge) => {
      const source = String(edge.source || "");
      if (!outgoing.has(source)) outgoing.set(source, []);
      outgoing.get(source).push(edge);
    });

    const targetNodes = (sourceId, kind) => {
      return (outgoing.get(sourceId) || [])
        .map((edge) => nodeById.get(String(edge.target || "")))
        .filter((node) => node && (!kind || node.kind === kind));
    };

    const vulnerabilityNodes = nodes.filter((node) => node && node.kind === "vulnerability");
    if (vulnerabilityNodes.length === 0) {
      els.graphOut.innerHTML = '<div class="empty">暂无漏洞知识图谱数据</div>';
      return;
    }

    const cards = vulnerabilityNodes.map((vuln) => {
      const vulnId = String(vuln.id || "");
      const cweNode = targetNodes(vulnId, "cwe")[0];
      const insightNode = targetNodes(vulnId, "ai_insight")[0];
      const insightId = insightNode ? String(insightNode.id || "") : "";
      const fixNodes = insightId ? targetNodes(insightId, "fix_pattern") : [];
      const caseNodes = targetNodes(vulnId, "reference_case");
      const cwe = vuln.cwe || (cweNode && cweNode.title) || "-";
      const fileLine = (vuln.file || "-") + ":" + (vuln.line || 0);

      const fixHtml = fixNodes.length
        ? fixNodes.map((fix) => '<span class="chip">' + escapeHtml(fix.title || fix.id || "-") + "</span>").join("")
        : '<span class="muted">无</span>';
      const caseHtml = caseNodes.length
        ? caseNodes.map((item) => {
          const title = escapeHtml(item.title || item.id || "参考案例");
          const summaryText = escapeHtml(item.summary || "");
          const url = String(item.source_url || "").trim();
          const link = url
            ? '<a href="' + escapeAttr(url) + '" target="_blank" rel="noopener noreferrer">' + title + "</a>"
            : "<strong>" + title + "</strong>";
          return "<li>" + link + (summaryText ? '<div class="muted">' + summaryText + "</div>" : "") + "</li>";
        }).join("")
        : '<li class="muted">无</li>';

      return (
        '<article class="kg-card">' +
        '<div class="kg-card-head">' +
        '<div><div class="muted">漏洞类型</div><h3>' + escapeHtml(vuln.title || "Unknown") + "</h3></div>" +
        '<span class="badge ' + riskClass(vuln.risk_score) + '">Risk ' + escapeHtml(vuln.risk_score ?? "-") + "</span>" +
        "</div>" +
        '<div class="meta-grid">' +
        '<div><span>文件与行号</span><strong>' + escapeHtml(fileLine) + "</strong></div>" +
        '<div><span>Severity</span><strong>' + escapeHtml(vuln.severity || "-") + "</strong></div>" +
        '<div><span>Risk Score</span><strong>' + escapeHtml(vuln.risk_score ?? "-") + "</strong></div>" +
        '<div><span>CWE</span><strong>' + escapeHtml(cwe) + "</strong></div>" +
        "</div>" +
        '<div class="kg-section"><div class="muted">AI Insight</div><p>' + escapeHtml((insightNode && insightNode.text) || "无") + "</p></div>" +
        '<div class="kg-section"><div class="muted">Fix Pattern</div><div class="chip-row">' + fixHtml + "</div></div>" +
        '<div class="kg-section"><div class="muted">Reference Case</div><ul class="case-list">' + caseHtml + "</ul></div>" +
        "</article>"
      );
    }).join("");

    els.graphOut.innerHTML =
      '<div class="graph-summary-grid">' +
      '<div class="mini-kpi"><div class="kpi-label">漏洞节点</div><div class="kpi-value">' + escapeHtml(summary.vulnerability_count ?? vulnerabilityNodes.length) + "</div></div>" +
      '<div class="mini-kpi"><div class="kpi-label">知识节点</div><div class="kpi-value">' + escapeHtml(summary.node_count ?? nodes.length) + "</div></div>" +
      '<div class="mini-kpi"><div class="kpi-label">关系数量</div><div class="kpi-value">' + escapeHtml(summary.edge_count ?? edges.length) + "</div></div>" +
      '<div class="mini-kpi"><div class="kpi-label">AI 模式</div><div class="kpi-value">' + escapeHtml(summary.ai_mode || "-") + "</div></div>" +
      "</div>" +
      cards;
  }

  async function refreshHealth() {
    try {
      await call("/health");
      els.topStatus.textContent = t("online");
    } catch {
      els.topStatus.textContent = t("offline");
    }
  }

  async function runAnalyze() {
    if (running) return;
    setError("");
    setRunning(true);
    setTopbarState("scanning");
    setJobProgress({ status: "scanning", stage: "detect", progress: 50, message: "正在执行安全扫描" });

    const payload = {
      input_type: inputType,
      code: els.codeInput.value,
      repo_url: els.repoUrl.value,
      language: inputType === "code" ? els.languageSelect.value : "auto"
    };

    try {
      // Use the /scan endpoint (synchronous) — the canonical API contract
      const result = await call("/scan", "POST", payload);
      lastAnalysisResult = result;
      updateOverview(lastAnalysisResult);
      renderFindings(lastAnalysisResult);
      setRawJson(lastAnalysisResult);
      setTopbarState("completed");
      setJobProgress({ status: "completed", stage: "done", progress: 100, message: "扫描完成" });
    } catch (e) {
      setError(String(e));
      setTopbarState("failed");
      setJobProgress({ status: "failed", stage: "detect", progress: 0, message: "扫描失败" });
    } finally {
      setRunning(false);
    }
  }

  async function runReset() {
    try {
      const data = await call("/reset", "POST");
      setRawJson(data);
      els.graphOut.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      setError("重置失败：" + String(e));
    }
  }

  async function runTests() {
    try {
      const data = await call("/run-tests", "POST");
      setRawJson(data);
      els.graphOut.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      setError("测试失败：" + String(e));
    }
  }

  async function showGraph() {
    try {
      const data = await call("/graph", "GET");
      renderCallGraph(data);
      setRawJson(data);
    } catch (e) {
      setError("调用图获取失败：" + String(e));
    }
  }

  async function showKnowledgeGraph() {
    if (!lastAnalysisResult || !Array.isArray(lastAnalysisResult.findings) || lastAnalysisResult.findings.length === 0) {
      els.graphOut.textContent = "请先完成一次漏洞分析，再查看知识图谱。";
      return;
    }
    const aiMode = els.kgAiMode ? els.kgAiMode.value : "rule";
    const modelName = els.kgModelName ? els.kgModelName.value.trim() : "";
    const apiKey = els.kgApiKey ? els.kgApiKey.value.trim() : "";
    const syncNeo4j = els.kgSyncNeo4j ? els.kgSyncNeo4j.checked : false;
    const payload = {
      vulnerabilities: lastAnalysisResult.findings,
      ai_mode: aiMode,
      sync_neo4j: syncNeo4j
    };
    if (modelName) payload.model_name = modelName;
    if (apiKey) payload.api_key = apiKey;
    try {
      const data = await call("/knowledge-graph", "POST", payload);
      renderKnowledgeGraph(data.graph || data);
      setRawJson(data);
    } catch (e) {
      setError("知识图谱获取失败：" + String(e));
    }
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(String(text || ""));
    } catch {
      setError("复制失败：当前浏览器环境不支持剪贴板写入。");
    }
  }

  function bindEvents() {
    els.segCode.addEventListener("click", () => setInputType("code"));
    els.segGithub.addEventListener("click", () => setInputType("github"));
    els.analyzeInputBtn.addEventListener("click", runAnalyze);
    els.resetBtn.addEventListener("click", runReset);
    els.testsBtn.addEventListener("click", runTests);
    els.graphBtn.addEventListener("click", showGraph);
    els.kgBtn.addEventListener("click", showKnowledgeGraph);
    els.copyJsonBtn.addEventListener("click", () => copyText(els.rawOut.textContent));
    els.langSwitch.addEventListener("change", () => {
      currentLang = els.langSwitch.value;
      applyI18n();
      setTopbarState(els.topJob.textContent);
      refreshHealth();
      updateOverview(lastAnalysisResult || { findings: [] });
    });
    // 语言过滤器事件
    document.getElementById("langFilterBar").addEventListener("click", function (e) {
      const chip = e.target.closest(".lang-chip");
      if (!chip) return;
      activeLangFilter = chip.dataset.lang || "all";
      this.querySelectorAll(".lang-chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      if (lastAnalysisResult) {
        renderFindings(lastAnalysisResult);
      }
    });
  }

  function applyI18n() {
    document.getElementById("productSub").textContent = t("productSub");
    document.getElementById("labelService").textContent = t("service");
    document.getElementById("labelEngine").textContent = t("engine");
    document.getElementById("labelJob").textContent = t("job");
    document.getElementById("navAnalyze").textContent = t("navAnalyze");
    document.getElementById("navFindings").textContent = t("navFindings");
    document.getElementById("navGraph").textContent = t("navGraph");
    document.getElementById("navRaw").textContent = t("navRaw");
    document.getElementById("titleOverview").textContent = t("titleOverview");
    document.getElementById("titleAnalyze").textContent = t("titleAnalyze");
    document.getElementById("titleProgress").textContent = t("titleProgress");
    document.getElementById("titleFindings").textContent = t("titleFindings");
    document.getElementById("titleDetail").textContent = t("titleDetail");
    document.getElementById("titleAdvanced").textContent = t("titleAdvanced");
    document.getElementById("titleRaw").textContent = t("titleRaw");
    document.getElementById("kpiLabelFindings").textContent = t("kpiFindings");
    document.getElementById("kpiLabelMaxRisk").textContent = t("kpiMaxRisk");
    document.getElementById("kpiLabelCritical").textContent = t("kpiCritical");
    document.getElementById("kpiLabelEngine").textContent = t("kpiEngine");
    document.getElementById("kpiLabelSkipped").textContent = t("kpiSkipped");
    document.getElementById("segCode").textContent = t("segCode");
    document.getElementById("segGithub").textContent = t("segGithub");
    document.getElementById("analyzeInputBtn").textContent = t("analyzeBtn");
    document.getElementById("resetBtn").textContent = t("resetBtn");
    document.getElementById("testsBtn").textContent = t("testsBtn");
    document.getElementById("copyJsonBtn").textContent = t("copyJson");
    // 知识图谱 AI 控件 I18N
    const labelKgAiMode = document.getElementById("labelKgAiMode");
    const labelKgModelName = document.getElementById("labelKgModelName");
    const labelKgApiKey = document.getElementById("labelKgApiKey");
    const labelKgSyncNeo4j = document.getElementById("labelKgSyncNeo4j");
    if (labelKgAiMode) labelKgAiMode.textContent = t("kgAiMode");
    if (labelKgModelName) labelKgModelName.textContent = t("kgModelName");
    if (labelKgApiKey) labelKgApiKey.textContent = t("kgApiKey");
    if (labelKgSyncNeo4j) labelKgSyncNeo4j.textContent = t("kgSyncNeo4j");
    if (els.kgModelName) els.kgModelName.placeholder = t("phModelName");
    if (els.kgApiKey) els.kgApiKey.placeholder = t("phApiKey");
    const steps = document.querySelectorAll(".step");
    if (steps.length === 4) {
      steps[0].textContent = t("stepPrepare");
      steps[1].textContent = t("stepDetect");
      steps[2].textContent = t("stepReport");
      steps[3].textContent = t("stepDone");
    }
  }

  function initDefaults() {
    currentLang = "zh-CN";
    els.langSwitch.value = currentLang;
    applyI18n();
    setInputType("code");
    setTopbarState(t("idle"));
    updateOverview({ findings: [] });
    renderFindings({ findings: [] });
    setRawJson({ status: "ready" });
    setError("");
  }

  async function init() {
    bindEvents();
    initDefaults();
    await refreshHealth();
  }

  window.onerror = function (message, source, lineno, colno) {
    setError("前端脚本错误: " + message + " @ " + source + ":" + lineno + ":" + colno);
  };

  init();
})();
