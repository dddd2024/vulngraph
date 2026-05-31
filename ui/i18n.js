/**
 * i18n Module - Internationalization support
 *
 * Provides bilingual support (zh-CN / en-US) for VulnPatch UI.
 * Team Member Assignment: Member 4 (API, UI & Report)
 */

const VulnPatchI18n = (function() {
  let currentLang = "zh-CN";

  const translations = {
    "zh-CN": {
      // Navigation
      "nav.overview": "概览",
      "nav.findings": "漏洞列表",
      "nav.graph": "调用图",
      "nav.knowledge": "知识图谱",
      "nav.raw": "原始 JSON",

      // Input
      "input.code": "代码片段",
      "input.repo": "本地仓库",
      "input.github": "GitHub 仓库",
      "input.language": "语言",
      "input.language.auto": "自动检测",
      "input.placeholder.code": "粘贴代码片段...",
      "input.placeholder.repo": "输入本地仓库路径...",
      "input.placeholder.github": "输入 GitHub 仓库 URL...",
      "input.analyze": "开始分析",

      // Overview
      "overview.title": "扫描概览",
      "overview.total": "总漏洞数",
      "overview.confirmed": "已确认",
      "overview.suspicious": "可疑",
      "overview.rejected": "已排除",
      "overview.risk": "风险评分",
      "overview.languages": "语言",
      "overview.files": "扫描文件",

      // Findings
      "findings.title": "漏洞列表",
      "findings.filter": "语言筛选",
      "findings.filter.all": "全部",
      "findings.sort": "排序",
      "findings.sort.risk": "按风险分",
      "findings.sort.severity": "按严重度",
      "findings.sort.confidence": "按置信度",
      "findings.empty": "未发现漏洞",
      "findings.details": "漏洞详情",
      "findings.type": "类型",
      "findings.severity": "严重度",
      "findings.confidence": "置信度",
      "findings.location": "位置",
      "findings.file": "文件",
      "findings.line": "行号",
      "findings.engine": "检测引擎",
      "findings.rule": "规则 ID",
      "findings.cwe": "CWE",
      "findings.message": "描述",
      "findings.snippet": "代码片段",
      "findings.call_chain": "调用链",
      "findings.risk_score": "风险评分",
      "findings.verdict": "裁决",

      // Severity levels
      "severity.error": "高危",
      "severity.warn": "中危",
      "severity.info": "低危",

      // Verdicts
      "verdict.confirmed": "已确认",
      "verdict.suspicious": "可疑",
      "verdict.rejected": "已排除",
      "verdict.pending": "待定",

      // Confidence
      "confidence.high": "高",
      "confidence.medium": "中",
      "confidence.low": "低",

      // Graph
      "graph.title": "函数调用图",
      "graph.empty": "无调用图数据",

      // Knowledge
      "knowledge.title": "漏洞知识图谱",
      "knowledge.insight": "AI 分析",
      "knowledge.fix": "修复建议",
      "knowledge.reference": "参考案例",

      // Status
      "status.idle": "等待输入",
      "status.scanning": "正在扫描",
      "status.completed": "扫描完成",
      "status.failed": "扫描失败",

      // Errors
      "error.generic": "发生错误",
      "error.api": "API 调用失败",

      // Actions
      "action.copy": "复制",
      "action.copy.success": "已复制到剪贴板",
      "action.close": "关闭"
    },

    "en-US": {
      // Navigation
      "nav.overview": "Overview",
      "nav.findings": "Findings",
      "nav.graph": "Call Graph",
      "nav.knowledge": "Knowledge Graph",
      "nav.raw": "Raw JSON",

      // Input
      "input.code": "Code Snippet",
      "input.repo": "Local Repository",
      "input.github": "GitHub Repository",
      "input.language": "Language",
      "input.language.auto": "Auto Detect",
      "input.placeholder.code": "Paste code snippet...",
      "input.placeholder.repo": "Enter local repository path...",
      "input.placeholder.github": "Enter GitHub repository URL...",
      "input.analyze": "Start Analysis",

      // Overview
      "overview.title": "Scan Overview",
      "overview.total": "Total Findings",
      "overview.confirmed": "Confirmed",
      "overview.suspicious": "Suspicious",
      "overview.rejected": "Rejected",
      "overview.risk": "Risk Score",
      "overview.languages": "Languages",
      "overview.files": "Scanned Files",

      // Findings
      "findings.title": "Findings List",
      "findings.filter": "Language Filter",
      "findings.filter.all": "All",
      "findings.sort": "Sort",
      "findings.sort.risk": "By Risk Score",
      "findings.sort.severity": "By Severity",
      "findings.sort.confidence": "By Confidence",
      "findings.empty": "No findings detected",
      "findings.details": "Finding Details",
      "findings.type": "Type",
      "findings.severity": "Severity",
      "findings.confidence": "Confidence",
      "findings.location": "Location",
      "findings.file": "File",
      "findings.line": "Line",
      "findings.engine": "Detection Engine",
      "findings.rule": "Rule ID",
      "findings.cwe": "CWE",
      "findings.message": "Description",
      "findings.snippet": "Code Snippet",
      "findings.call_chain": "Call Chain",
      "findings.risk_score": "Risk Score",
      "findings.verdict": "Verdict",

      // Severity levels
      "severity.error": "High",
      "severity.warn": "Medium",
      "severity.info": "Low",

      // Verdicts
      "verdict.confirmed": "Confirmed",
      "verdict.suspicious": "Suspicious",
      "verdict.rejected": "Rejected",
      "verdict.pending": "Pending",

      // Confidence
      "confidence.high": "High",
      "confidence.medium": "Medium",
      "confidence.low": "Low",

      // Graph
      "graph.title": "Function Call Graph",
      "graph.empty": "No call graph data",

      // Knowledge
      "knowledge.title": "Vulnerability Knowledge Graph",
      "knowledge.insight": "AI Insight",
      "knowledge.fix": "Fix Pattern",
      "knowledge.reference": "Reference Case",

      // Status
      "status.idle": "Waiting for input",
      "status.scanning": "Scanning",
      "status.completed": "Scan completed",
      "status.failed": "Scan failed",

      // Errors
      "error.generic": "An error occurred",
      "error.api": "API call failed",

      // Actions
      "action.copy": "Copy",
      "action.copy.success": "Copied to clipboard",
      "action.close": "Close"
    }
  };

  /**
   * Get current language
   * @returns {string}
   */
  function getCurrentLang() {
    return currentLang;
  }

  /**
   * Set current language
   * @param {string} lang
   */
  function setCurrentLang(lang) {
    if (translations[lang]) {
      currentLang = lang;
    }
  }

  /**
   * Get translation for a key
   * @param {string} key
   * @returns {string}
   */
  function t(key) {
    const dict = translations[currentLang] || translations["zh-CN"];
    return dict[key] || key;
  }

  /**
   * Get all available languages
   * @returns {array}
   */
  function getAvailableLanguages() {
    return Object.keys(translations);
  }

  return {
    getCurrentLang,
    setCurrentLang,
    t,
    getAvailableLanguages
  };
})();