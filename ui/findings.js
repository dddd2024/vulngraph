/**
 * Findings Module - Finding list and detail rendering
 *
 * Provides finding list and detail rendering for VulnPatch UI.
 * Team Member Assignment: Member 4 (API, UI & Report)
 */

const VulnPatchFindings = (function() {
  /**
   * Render findings list
   * @param {object} result - Scan result with findings
   * @param {object} container - DOM container element
   * @param {function} onSelect - Callback when finding is selected
   */
  function renderList(result, container, onSelect) {
    const vulns = Array.isArray(result && result.findings) ? result.findings.slice() : [];

    // Sort by risk score (descending)
    vulns.sort(function(a, b) {
      return (b.risk_score || 0) - (a.risk_score || 0);
    });

    // Filter by language
    const selectedLang = VulnPatchState.getSelectedLanguage();
    const filtered = selectedLang === "all"
      ? vulns
      : vulns.filter(function(v) {
          const lang = (v.metadata && v.metadata.language) || "";
          return lang.toLowerCase() === selectedLang.toLowerCase();
        });

    container.innerHTML = "";

    if (filtered.length === 0) {
      container.innerHTML = "<div class='empty-state'>" + VulnPatchI18n.t("findings.empty") + "</div>";
      return;
    }

    filtered.forEach(function(v) {
      const item = document.createElement("div");
      item.className = "finding-item";
      item.setAttribute("data-id", v.id);

      const severityClass = "severity-" + (v.severity || "warn").toLowerCase();
      const verdictClass = "verdict-" + (v.verdict || "pending");

      item.innerHTML = [
        "<div class='finding-header'>",
        "<span class='finding-type'>" + (v.type || "Unknown") + "</span>",
        "<span class='finding-severity " + severityClass + "'>" + VulnPatchI18n.t("severity." + (v.severity || "warn").toLowerCase()) + "</span>",
        "<span class='finding-verdict " + verdictClass + "'>" + VulnPatchI18n.t("verdict." + (v.verdict || "pending")) + "</span>",
        "</div>",
        "<div class='finding-meta'>",
        "<span class='finding-file'>" + (v.file || v.file_path || "") + "</span>",
        "<span class='finding-line'>:" + (v.line || v.start_line || 0) + "</span>",
        "<span class='finding-risk'>风险: " + (v.risk_score || 0) + "</span>",
        "</div>"
      ].join("");

      item.addEventListener("click", function() {
        VulnPatchState.setSelectedFindingId(v.id);
        if (onSelect) onSelect(v);
      });

      container.appendChild(item);
    });
  }

  /**
   * Render finding detail
   * @param {object} finding - Finding object
   * @param {object} container - DOM container element
   */
  function renderDetail(finding, container) {
    if (!finding) {
      container.innerHTML = "<div class='empty-state'>未选择漏洞</div>";
      return;
    }

    const severityClass = "severity-" + (finding.severity || "warn").toLowerCase();
    const verdictClass = "verdict-" + (finding.verdict || "pending");

    container.innerHTML = [
      "<div class='detail-header'>",
      "<h3>" + VulnPatchI18n.t("findings.details") + "</h3>",
      "<button class='close-btn' onclick='VulnPatchFindings.closeDetail()'>" + VulnPatchI18n.t("action.close") + "</button>",
      "</div>",
      "<div class='detail-content'>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.type") + "</label><span>" + (finding.type || "Unknown") + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.severity") + "</label><span class='" + severityClass + "'>" + VulnPatchI18n.t("severity." + (finding.severity || "warn").toLowerCase()) + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.confidence") + "</label><span>" + VulnPatchI18n.t("confidence." + (finding.confidence || "medium")) + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.verdict") + "</label><span class='" + verdictClass + "'>" + VulnPatchI18n.t("verdict." + (finding.verdict || "pending")) + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.risk_score") + "</label><span>" + (finding.risk_score || 0) + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.file") + "</label><span>" + (finding.file || finding.file_path || "") + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.line") + "</label><span>" + (finding.line || finding.start_line || 0) + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.engine") + "</label><span>" + (finding.engine || "") + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.rule") + "</label><span>" + (finding.rule_id || "") + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.cwe") + "</label><span>" + (finding.cwe || "") + "</span></div>",
      "<div class='detail-row'><label>" + VulnPatchI18n.t("findings.message") + "</label><span>" + (finding.message || "") + "</span></div>",
      "</div>"
    ].join("");

    // Add snippet if available
    if (finding.snippet) {
      const snippetSection = document.createElement("div");
      snippetSection.className = "detail-section";
      snippetSection.innerHTML = [
        "<h4>" + VulnPatchI18n.t("findings.snippet") + "</h4>",
        "<pre class='code-snippet'>" + finding.snippet + "</pre>"
      ].join("");
      container.appendChild(snippetSection);
    }

    // Add call chain if available
    if (finding.call_chain && finding.call_chain.length > 0) {
      const chainSection = document.createElement("div");
      chainSection.className = "detail-section";
      chainSection.innerHTML = [
        "<h4>" + VulnPatchI18n.t("findings.call_chain") + "</h4>",
        "<div class='call-chain'>" + finding.call_chain.join(" → ") + "</div>"
      ].join("");
      container.appendChild(chainSection);
    }
  }

  /**
   * Close detail panel
   */
  function closeDetail() {
    VulnPatchState.setSelectedFindingId(null);
    const detailPanel = document.getElementById("finding-detail");
    if (detailPanel) {
      detailPanel.innerHTML = "";
      detailPanel.style.display = "none";
    }
  }

  /**
   * Update overview panel
   * @param {object} result - Scan result
   */
  function updateOverview(result) {
    const vulns = Array.isArray(result && result.findings) ? result.findings : [];

    const confirmed = vulns.filter(function(v) { return v.verdict === "confirmed"; }).length;
    const suspicious = vulns.filter(function(v) { return v.verdict === "suspicious"; }).length;
    const rejected = vulns.filter(function(v) { return v.verdict === "rejected"; }).length;

    const avgRisk = vulns.length > 0
      ? vulns.reduce(function(sum, v) { return sum + (v.risk_score || 0); }, 0) / vulns.length
      : 0;

    const languages = result.summary && result.summary.languages
      ? result.summary.languages.join(", ")
      : "";

    const files = result.summary && result.summary.scanned_files
      ? result.summary.scanned_files.length
      : 0;

    // Update DOM elements
    const overviewEl = document.getElementById("overview");
    if (overviewEl) {
      overviewEl.innerHTML = [
        "<div class='overview-item'><span class='label'>" + VulnPatchI18n.t("overview.total") + "</span><span class='value'>" + vulns.length + "</span></div>",
        "<div class='overview-item'><span class='label'>" + VulnPatchI18n.t("overview.confirmed") + "</span><span class='value confirmed'>" + confirmed + "</span></div>",
        "<div class='overview-item'><span class='label'>" + VulnPatchI18n.t("overview.suspicious") + "</span><span class='value suspicious'>" + suspicious + "</span></div>",
        "<div class='overview-item'><span class='label'>" + VulnPatchI18n.t("overview.rejected") + "</span><span class='value rejected'>" + rejected + "</span></div>",
        "<div class='overview-item'><span class='label'>" + VulnPatchI18n.t("overview.risk") + "</span><span class='value'>" + Math.round(avgRisk) + "</span></div>",
        "<div class='overview-item'><span class='label'>" + VulnPatchI18n.t("overview.languages") + "</span><span class='value'>" + languages + "</span></div>",
        "<div class='overview-item'><span class='label'>" + VulnPatchI18n.t("overview.files") + "</span><span class='value'>" + files + "</span></div>"
      ].join("");
    }
  }

  return {
    renderList,
    renderDetail,
    closeDetail,
    updateOverview
  };
})();