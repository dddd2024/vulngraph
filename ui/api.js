/**
 * API Module - HTTP request utilities
 *
 * Provides centralized API call handling for VulnPatch UI.
 * Team Member Assignment: Member 4 (API, UI & Report)
 */

const VulnPatchAPI = (function() {
  const BASE_URL = "";

  /**
   * Make an HTTP request to the API
   * @param {string} path - API endpoint path
   * @param {string} method - HTTP method (GET, POST, etc.)
   * @param {object|null} body - Request body (for POST/PUT)
   * @returns {Promise<object>} - Response data
   */
  async function call(path, method, body = null) {
    const url = BASE_URL + path;
    const opts = {
      method: method,
      headers: { "Content-Type": "application/json" }
    };
    if (body !== null) {
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(url, opts);
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error("API error: " + resp.status + " " + text);
    }
    return resp.json();
  }

  /**
   * Run a scan
   * @param {object} payload - Scan request payload
   * @returns {Promise<object>} - Scan result
   */
  async function scan(payload) {
    return call("/scan", "POST", payload);
  }

  /**
   * Get scan findings view (UI-friendly)
   * @param {string} scanId - Scan ID
   * @returns {Promise<object>} - ScanView with FindingView list
   */
  async function getFindingsView(scanId) {
    return call("/scans/" + scanId + "/findings/view", "GET");
  }

  /**
   * Get scan findings (raw)
   * @param {string} scanId - Scan ID
   * @returns {Promise<array>} - RawFinding list
   */
  async function getFindings(scanId) {
    return call("/scans/" + scanId + "/findings", "GET");
  }

  /**
   * Get scan evidence
   * @param {string} scanId - Scan ID
   * @returns {Promise<array>} - EvidenceBundle list
   */
  async function getEvidence(scanId) {
    return call("/scans/" + scanId + "/evidence", "GET");
  }

  /**
   * Get agent logs
   * @param {string} scanId - Scan ID
   * @returns {Promise<array>} - AgentLog list
   */
  async function getAgentLogs(scanId) {
    return call("/scans/" + scanId + "/agents/logs", "GET");
  }

  /**
   * Get graph data
   * @returns {Promise<object>} - Graph data
   */
  async function getGraph() {
    return call("/graph", "GET");
  }

  /**
   * Get knowledge graph
   * @param {object} payload - Request payload
   * @returns {Promise<object>} - Knowledge graph data
   */
  async function getKnowledgeGraph(payload) {
    return call("/knowledge-graph", "POST", payload);
  }

  /**
   * Get report (JSON format)
   * @param {string} scanId - Scan ID
   * @returns {Promise<object>} - JSON report
   */
  async function getReportJson(scanId) {
    return call("/scans/" + scanId + "/report/json", "GET");
  }

  /**
   * Get report (Markdown format)
   * @param {string} scanId - Scan ID
   * @returns {Promise<string>} - Markdown content
   */
  async function getReportMarkdown(scanId) {
    const url = BASE_URL + "/scans/" + scanId + "/report/markdown";
    const resp = await fetch(url);
    return resp.text();
  }

  /**
   * Get report (HTML format)
   * @param {string} scanId - Scan ID
   * @returns {Promise<string>} - HTML content
   */
  async function getReportHtml(scanId) {
    const url = BASE_URL + "/scans/" + scanId + "/report/html";
    const resp = await fetch(url);
    return resp.text();
  }

  return {
    call,
    scan,
    getFindingsView,
    getFindings,
    getEvidence,
    getAgentLogs,
    getGraph,
    getKnowledgeGraph,
    getReportJson,
    getReportMarkdown,
    getReportHtml
  };
})();