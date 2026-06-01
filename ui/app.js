/**
 * VulnPatch UI - Main Application Coordinator
 *
 * This file coordinates the modular UI components:
 * - api.js: HTTP request utilities
 * - state.js: Application state management
 * - i18n.js: Internationalization support
 * - findings.js: Finding list and detail rendering
 * - graph.js: Graph visualization
 *
 * Team Member Assignment: Member 4 (API, UI & Report)
 */

(function() {
  // DOM element references
  const els = {
    codeInput: null,
    repoPath: null,
    repoUrl: null,
    languageSelect: null,
    languageFilter: null,
    langSelect: null,
    analyzeBtn: null,
    findingsList: null,
    findingDetail: null,
    overview: null,
    graphContainer: null,
    knowledgeContainer: null,
    rawJson: null,
    copyJsonBtn: null,
    statusMessage: null,
    statusProgress: null,
    errorDisplay: null
  };

  // Error handling
  let errorTimeout = null;

  function setError(msg) {
    if (els.errorDisplay) {
      els.errorDisplay.textContent = msg;
      els.errorDisplay.classList.remove("hidden");
    }
    if (errorTimeout) clearTimeout(errorTimeout);
    errorTimeout = setTimeout(function() {
      if (els.errorDisplay) {
        els.errorDisplay.classList.add("hidden");
      }
    }, 5000);
  }

  function setStatus(msg, progress) {
    if (els.statusMessage) els.statusMessage.textContent = msg;
    if (els.statusProgress) els.statusProgress.textContent = progress || "";
  }

  function sleep(ms) {
    return new Promise(function(resolve) { setTimeout(resolve, ms); });
  }

  // Initialize DOM references
  function initElements() {
    els.codeInput = document.getElementById("code-input");
    els.repoPath = document.getElementById("repo-path");
    els.repoUrl = document.getElementById("repo-url");
    els.languageSelect = document.getElementById("language-select");
    els.languageFilter = document.getElementById("language-filter");
    els.langSelect = document.getElementById("lang-select");
    els.analyzeBtn = document.getElementById("analyze-btn");
    els.findingsList = document.getElementById("findings-list");
    els.findingDetail = document.getElementById("finding-detail");
    els.overview = document.getElementById("overview");
    els.graphContainer = document.getElementById("graph-container");
    els.knowledgeContainer = document.getElementById("knowledge-container");
    els.rawJson = document.getElementById("raw-json");
    els.copyJsonBtn = document.getElementById("copy-json-btn");
    els.statusMessage = document.getElementById("status-message");
    els.statusProgress = document.getElementById("status-progress");
    els.errorDisplay = document.getElementById("error-display");
  }

  // Set raw JSON display
  function setRawJson(obj) {
    if (els.rawJson) {
      els.rawJson.textContent = JSON.stringify(obj, null, 2);
    }
  }

  // Main analysis function
  async function runAnalyze() {
    if (VulnPatchState.isRunning()) return;
    setError("");
    VulnPatchState.setRunning(true);
    setStatus(VulnPatchI18n.t("status.scanning"), "50%");

    const inputType = VulnPatchState.getInputType();
    const payload = {
      input_type: inputType,
      code: els.codeInput ? els.codeInput.value : "",
      repo_url: els.repoUrl ? els.repoUrl.value : "",
      language: inputType === "code" && els.languageSelect ? els.languageSelect.value : "auto"
    };

    try {
      // Step 1: Call /scan to get raw result
      const result = await VulnPatchAPI.scan(payload);
      VulnPatchState.setLastResult(result);

      // Step 2: Save raw result for JSON display
      setRawJson(result);

      // Step 3: Try to get FindingView for UI rendering
      let displayData = result; // fallback to raw result
      if (result.scan_id) {
        try {
          const view = await VulnPatchAPI.getFindingsView(result.scan_id);
          if (view && view.findings) {
            displayData = view;
          }
        } catch (viewErr) {
          console.warn("FindingView fetch failed, using raw result:", viewErr);
        }
      }

      // Step 4: Render using view (or fallback to raw)
      VulnPatchFindings.updateOverview(displayData);
      VulnPatchFindings.renderList(displayData, els.findingsList, function(finding) {
        VulnPatchFindings.renderDetail(finding, els.findingDetail);
        els.findingDetail.style.display = "block";
      });

      setStatus(VulnPatchI18n.t("status.completed"), "100%");

      // Load graphs (use raw result for graph data)
      VulnPatchGraph.loadCallGraph(els.graphContainer);
      VulnPatchGraph.loadKnowledgeGraph(result, els.knowledgeContainer);

    } catch (e) {
      setError(VulnPatchI18n.t("error.api") + ": " + e);
      setStatus(VulnPatchI18n.t("status.failed"), "");
    } finally {
      VulnPatchState.setRunning(false);
    }
  }

  // Tab switching
  function setupTabs() {
    // Input type tabs
    const inputTabs = document.querySelectorAll(".tab-btn");
    inputTabs.forEach(function(btn) {
      btn.addEventListener("click", function() {
        inputTabs.forEach(function(b) { b.classList.remove("active"); });
        btn.classList.add("active");

        const type = btn.getAttribute("data-type");
        VulnPatchState.setInputType(type);

        // Show/hide input areas
        document.getElementById("code-input-area").classList.toggle("hidden", type !== "code");
        document.getElementById("path-input-area").classList.toggle("hidden", type !== "path");
        document.getElementById("github-input-area").classList.toggle("hidden", type !== "github");
      });
    });

    // Bottom panel tabs
    const bottomTabs = document.querySelectorAll(".bottom-tab-btn");
    bottomTabs.forEach(function(btn) {
      btn.addEventListener("click", function() {
        bottomTabs.forEach(function(b) { b.classList.remove("active"); });
        btn.classList.add("active");

        const tab = btn.getAttribute("data-tab");
        document.getElementById("graph-panel").classList.toggle("hidden", tab !== "graph");
        document.getElementById("knowledge-panel").classList.toggle("hidden", tab !== "knowledge");
        document.getElementById("raw-panel").classList.toggle("hidden", tab !== "raw");
      });
    });
  }

  // Language filter
  function setupLanguageFilter() {
    if (els.languageFilter) {
      els.languageFilter.addEventListener("change", function() {
        VulnPatchState.setSelectedLanguage(els.languageFilter.value);
        const result = VulnPatchState.getLastResult();
        if (result) {
          VulnPatchFindings.renderList(result, els.findingsList, function(finding) {
            VulnPatchFindings.renderDetail(finding, els.findingDetail);
            els.findingDetail.style.display = "block";
          });
        }
      });
    }
  }

  // Language switch (i18n)
  function setupLanguageSwitch() {
    if (els.langSelect) {
      els.langSelect.addEventListener("change", function() {
        VulnPatchI18n.setCurrentLang(els.langSelect.value);
        // Re-render with new language
        const result = VulnPatchState.getLastResult();
        if (result) {
          VulnPatchFindings.updateOverview(result);
          VulnPatchFindings.renderList(result, els.findingsList, function(finding) {
            VulnPatchFindings.renderDetail(finding, els.findingDetail);
          });
        }
      });
    }
  }

  // Copy JSON button
  function setupCopyJson() {
    if (els.copyJsonBtn) {
      els.copyJsonBtn.addEventListener("click", function() {
        const text = els.rawJson ? els.rawJson.textContent : "";
        navigator.clipboard.writeText(text).then(function() {
          alert(VulnPatchI18n.t("action.copy.success"));
        });
      });
    }
  }

  // Initialize application
  function init() {
    initElements();
    setupTabs();
    setupLanguageFilter();
    setupLanguageSwitch();
    setupCopyJson();

    // Analyze button
    if (els.analyzeBtn) {
      els.analyzeBtn.addEventListener("click", runAnalyze);
    }

    // Initial state
    VulnPatchFindings.updateOverview({ findings: [] });
    VulnPatchFindings.renderList({ findings: [] }, els.findingsList, function() {});
    setStatus(VulnPatchI18n.t("status.idle"), "");
  }

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();