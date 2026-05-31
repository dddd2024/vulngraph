/**
 * Graph Module - Call graph and knowledge graph rendering
 *
 * Provides graph visualization for VulnPatch UI.
 * Team Member Assignment: Member 4 (API, UI & Report)
 */

const VulnPatchGraph = (function() {
  /**
   * Render call graph
   * @param {object} data - Graph data from API
   * @param {object} container - DOM container element
   */
  function renderCallGraph(data, container) {
    if (!data || !data.nodes || data.nodes.length === 0) {
      container.innerHTML = "<div class='empty-state'>" + VulnPatchI18n.t("graph.empty") + "</div>";
      return;
    }

    // Simple SVG-based graph rendering
    const width = container.clientWidth || 600;
    const height = container.clientHeight || 400;

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", width);
    svg.setAttribute("height", height);
    svg.style.background = "#1a1a2e";

    // Position nodes in a simple layout
    const nodePositions = {};
    const nodeCount = data.nodes.length;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 3;

    data.nodes.forEach(function(node, i) {
      const angle = (2 * Math.PI * i) / nodeCount;
      nodePositions[node.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle)
      };
    });

    // Draw edges
    if (data.edges) {
      data.edges.forEach(function(edge) {
        const from = nodePositions[edge.from];
        const to = nodePositions[edge.to];
        if (from && to) {
          const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
          line.setAttribute("x1", from.x);
          line.setAttribute("y1", from.y);
          line.setAttribute("x2", to.x);
          line.setAttribute("y2", to.y);
          line.setAttribute("stroke", "#4a4a6a");
          line.setAttribute("stroke-width", "2");
          svg.appendChild(line);
        }
      });
    }

    // Draw nodes
    data.nodes.forEach(function(node) {
      const pos = nodePositions[node.id];
      if (pos) {
        // Node circle
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", pos.x);
        circle.setAttribute("cy", pos.y);
        circle.setAttribute("r", "20");
        circle.setAttribute("fill", node.vulnerable ? "#e74c3c" : "#3498db");
        circle.setAttribute("stroke", "#fff");
        circle.setAttribute("stroke-width", "2");
        svg.appendChild(circle);

        // Node label
        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", pos.x);
        text.setAttribute("y", pos.y + 35);
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("fill", "#fff");
        text.setAttribute("font-size", "12");
        text.textContent = node.name || node.id;
        svg.appendChild(text);
      }
    });

    container.innerHTML = "";
    container.appendChild(svg);
  }

  /**
   * Render knowledge graph
   * @param {object} data - Knowledge graph data from API
   * @param {object} container - DOM container element
   */
  function renderKnowledgeGraph(data, container) {
    if (!data) {
      container.innerHTML = "<div class='empty-state'>无知识图谱数据</div>";
      return;
    }

    container.innerHTML = "";

    // AI Insight section
    if (data.ai_insight) {
      const insightSection = document.createElement("div");
      insightSection.className = "knowledge-section";
      insightSection.innerHTML = [
        "<h4>" + VulnPatchI18n.t("knowledge.insight") + "</h4>",
        "<div class='knowledge-content'>" + data.ai_insight + "</div>"
      ].join("");
      container.appendChild(insightSection);
    }

    // Fix Pattern section
    if (data.fix_pattern) {
      const fixSection = document.createElement("div");
      fixSection.className = "knowledge-section";
      fixSection.innerHTML = [
        "<h4>" + VulnPatchI18n.t("knowledge.fix") + "</h4>",
        "<pre class='code-snippet'>" + data.fix_pattern + "</pre>"
      ].join("");
      container.appendChild(fixSection);
    }

    // Reference Case section
    if (data.reference_case) {
      const refSection = document.createElement("div");
      refSection.className = "knowledge-section";
      refSection.innerHTML = [
        "<h4>" + VulnPatchI18n.t("knowledge.reference") + "</h4>",
        "<div class='knowledge-content'>" + data.reference_case + "</div>"
      ].join("");
      container.appendChild(refSection);
    }

    // CWE info section
    if (data.cwe_info) {
      const cweSection = document.createElement("div");
      cweSection.className = "knowledge-section";
      cweSection.innerHTML = [
        "<h4>CWE 信息</h4>",
        "<div class='knowledge-content'>",
        "<p><strong>ID:</strong> " + (data.cwe_info.id || "") + "</p>",
        "<p><strong>名称:</strong> " + (data.cwe_info.name || "") + "</p>",
        "<p><strong>描述:</strong> " + (data.cwe_info.description || "") + "</p>",
        "</div>"
      ].join("");
      container.appendChild(cweSection);
    }
  }

  /**
   * Load and render call graph
   * @param {object} container - DOM container element
   */
  async function loadCallGraph(container) {
    try {
      const data = await VulnPatchAPI.getGraph();
      renderCallGraph(data, container);
    } catch (e) {
      container.innerHTML = "<div class='error-state'>" + VulnPatchI18n.t("error.api") + ": " + e + "</div>";
    }
  }

  /**
   * Load and render knowledge graph
   * @param {object} result - Scan result
   * @param {object} container - DOM container element
   */
  async function loadKnowledgeGraph(result, container) {
    if (!result || !result.findings || result.findings.length === 0) {
      container.innerHTML = "<div class='empty-state'>无漏洞数据</div>";
      return;
    }

    try {
      const data = await VulnPatchAPI.getKnowledgeGraph({
        vulnerabilities: result.findings
      });
      renderKnowledgeGraph(data, container);
    } catch (e) {
      container.innerHTML = "<div class='error-state'>" + VulnPatchI18n.t("error.api") + ": " + e + "</div>";
    }
  }

  return {
    renderCallGraph,
    renderKnowledgeGraph,
    loadCallGraph,
    loadKnowledgeGraph
  };
})();