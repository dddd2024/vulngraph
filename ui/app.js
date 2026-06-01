/**
 * VulnPatch Frontend Application
 * 
 * 功能模块：
 * 1. 扫描接口调用 - 调用后端 /scan 接口执行代码审计
 * 2. 数据渲染 - 动态渲染漏洞列表和详情
 * 3. 报告预览 - 支持 JSON/Markdown/HTML 三种格式
 * 4. 报告导出 - 一键导出审计报告
 */

class VulnPatchApp {
  constructor() {
    // DOM元素引用
    this.elements = {
      // 状态与配置
      statusBadge: document.getElementById('statusBadge'),
      dirPath: document.getElementById('dirPath'),
      browseBtn: document.getElementById('browseBtn'),
      languageSelect: document.getElementById('languageSelect'),
      scanBtn: document.getElementById('scanBtn'),
      progressContainer: document.getElementById('progressContainer'),
      progressFill: document.getElementById('progressFill'),
      progressText: document.getElementById('progressText'),
      
      // AI模式配置
      analysisMode: document.getElementById('analysisMode'),
      aiConfig: document.getElementById('aiConfig'),
      apiKey: document.getElementById('apiKey'),
      aiProvider: document.getElementById('aiProvider'),
      
      // 统计数据
      statFiles: document.getElementById('statFiles'),
      statFindings: document.getElementById('statFindings'),
      statHigh: document.getElementById('statHigh'),
      statRisk: document.getElementById('statRisk'),
      
      // 导出按钮
      exportJsonBtn: document.getElementById('exportJsonBtn'),
      exportMarkdownBtn: document.getElementById('exportMarkdownBtn'),
      exportHtmlBtn: document.getElementById('exportHtmlBtn'),
      
      // 漏洞列表
      findingsList: document.getElementById('findingsList'),
      filterTabs: document.querySelectorAll('.filter-tab'),
      
      // 漏洞详情
      detailEmpty: document.getElementById('detailEmpty'),
      detailContent: document.getElementById('detailContent'),
      detailType: document.getElementById('detailType'),
      detailCwe: document.getElementById('detailCwe'),
      detailRule: document.getElementById('detailRule'),
      detailSeverity: document.getElementById('detailSeverity'),
      detailConfidence: document.getElementById('detailConfidence'),
      detailLocation: document.getElementById('detailLocation'),
      detailMessage: document.getElementById('detailMessage'),
      detailCode: document.getElementById('detailCode'),
      detailSuggestion: document.getElementById('detailSuggestion'),
      
      // 报告预览
      reportTabs: document.querySelectorAll('.report-tab'),
      reportContent: document.getElementById('reportContent')
    };
    
    // 全局状态
    this.currentFindings = [];
    this.currentEvidence = {};
    this.currentReport = { json: '', markdown: '', html: '' };
    
    // 初始化事件监听
    this.initEventListeners();
  }
  
  /**
   * 初始化所有事件监听器
   */
  initEventListeners() {
    // 浏览目录按钮
    this.elements.browseBtn.addEventListener('click', () => this.handleBrowseClick());
    
    // 扫描按钮
    this.elements.scanBtn.addEventListener('click', () => this.handleScanClick());
    
    // AI模式切换
    this.elements.analysisMode.addEventListener('change', () => this.handleModeChange());
    
    // 漏洞过滤标签
    this.elements.filterTabs.forEach(tab => {
      tab.addEventListener('click', () => this.handleFilterChange(tab.dataset.filter));
    });
    
    // 报告类型切换
    this.elements.reportTabs.forEach(tab => {
      tab.addEventListener('click', () => this.handleReportTabChange(tab.dataset.report));
    });
    
    // 导出按钮
    this.elements.exportJsonBtn.addEventListener('click', () => 
      this.exportReport('json', 'audit_report.json', 'application/json')
    );
    this.elements.exportMarkdownBtn.addEventListener('click', () => 
      this.exportReport('markdown', 'audit_report.md', 'text/markdown')
    );
    this.elements.exportHtmlBtn.addEventListener('click', () => 
      this.exportReport('html', 'audit_report.html', 'text/html')
    );
  }
  
  /**
   * 处理浏览目录按钮点击
   */
  handleBrowseClick() {
    this.elements.dirPath.removeAttribute('readonly');
    this.elements.dirPath.placeholder = '请输入目录路径，例如: /path/to/project';
    this.elements.dirPath.focus();
  }
  
  /**
   * 处理分析模式切换
   */
  handleModeChange() {
    const mode = this.elements.analysisMode.value;
    if (mode === 'ai') {
      this.elements.aiConfig.classList.remove('hidden');
      this.showToast('已切换到AI增强模式，可配置API密钥', 'success');
    } else {
      this.elements.aiConfig.classList.add('hidden');
      this.showToast('已切换到本地模式', 'success');
    }
  }
  
  /**
   * 处理扫描按钮点击
   */
  async handleScanClick() {
    const path = this.elements.dirPath.value.trim();
    if (!path) {
      this.showToast('请先选择代码目录', 'error');
      return;
    }
    
    await this.performScan(path);
  }
  
  /**
   * 处理漏洞过滤切换
   */
  handleFilterChange(filter) {
    // 更新标签状态
    this.elements.filterTabs.forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-filter="${filter}"]`).classList.add('active');
    
    // 渲染过滤后的漏洞列表
    this.renderFindings(filter);
  }
  
  /**
   * 处理报告类型切换
   */
  handleReportTabChange(reportType) {
    // 更新标签状态
    this.elements.reportTabs.forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-report="${reportType}"]`).classList.add('active');
    
    // 渲染报告内容
    this.renderReport(reportType);
  }
  
  /**
   * 执行扫描操作
   * @param {string} path - 代码目录路径
   */
  async performScan(path) {
    // 更新UI状态
    this.updateStatus('scanning', '扫描中');
    this.elements.scanBtn.disabled = true;
    this.elements.progressContainer.classList.remove('hidden');
    this.elements.progressFill.style.width = '0%';
    
    // 清空之前的结果
    this.clearResults();
    
    // 模拟扫描进度
    await this.simulateProgress();
    
    try {
      // 调用后端扫描接口
      const result = await this.callScanAPI(path);
      
      // 处理扫描结果
      await this.processScanResult(result);
      
      // 更新状态和UI
      this.updateStatus('ready', '扫描完成');
      this.enableExportButtons();
      this.showToast(`扫描完成，发现 ${this.currentFindings.length} 个漏洞`, 'success');
      
    } catch (error) {
      console.error('扫描失败:', error);
      this.updateStatus('ready', '扫描失败');
      this.showToast(error.message || '扫描过程中发生错误', 'error');
    } finally {
      // 完成进度条
      this.elements.progressFill.style.width = '100%';
      this.elements.progressText.textContent = '扫描完成';
      this.elements.scanBtn.disabled = false;
      
      // 隐藏进度条
      setTimeout(() => {
        this.elements.progressContainer.classList.add('hidden');
      }, 500);
    }
  }
  
  /**
   * 调用后端扫描API
   * @param {string} path - 代码目录路径
   * @returns {Object} - 扫描结果
   */
  async callScanAPI(path) {
    const language = this.elements.languageSelect.value === 'auto' ? null : this.elements.languageSelect.value;
    const mode = this.elements.analysisMode.value;
    
    // 构建请求数据
    const requestData = {
      input_type: 'path',
      repo_path: path,
      language: language,
      analysis_mode: mode
    };
    
    // 如果是AI模式，添加AI配置
    if (mode === 'ai') {
      const apiKey = this.elements.apiKey.value.trim();
      const provider = this.elements.aiProvider.value;
      
      if (apiKey) {
        requestData.api_key = apiKey;
      }
      requestData.ai_provider = provider;
    }
    
    const response = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestData)
    });
    
    const result = await response.json();
    
    if (!result.success) {
      throw new Error(result.message || '扫描失败');
    }
    
    return result;
  }
  
  /**
   * 处理扫描结果
   * @param {Object} result - 扫描结果对象
   */
  async processScanResult(result) {
    // 存储漏洞数据
    this.currentFindings = result.data.findings || [];
    
    // 构建证据映射
    this.currentEvidence = {};
    (result.data.evidence || []).forEach(ev => {
      if (ev.finding_id) {
        this.currentEvidence[ev.finding_id] = ev;
      }
    });
    
    // 存储JSON报告
    this.currentReport.json = JSON.stringify(result.data, null, 2);
    
    // 获取其他格式报告
    await this.fetchReports();
    
    // 更新统计数据
    this.updateStats(result.data.summary || {});
    
    // 渲染漏洞列表和报告
    this.renderFindings('all');
    this.renderReport('json');
  }
  
  /**
   * 获取报告内容
   */
  async fetchReports() {
    try {
      const [mdRes, htmlRes] = await Promise.all([
        fetch('/report/markdown'),
        fetch('/report/html')
      ]);
      
      this.currentReport.markdown = await mdRes.text();
      this.currentReport.html = await htmlRes.text();
    } catch (error) {
      console.warn('获取报告失败:', error);
    }
  }
  
  /**
   * 模拟扫描进度
   */
  async simulateProgress() {
    const progressSteps = [10, 25, 40, 55, 70, 85, 95];
    for (const percent of progressSteps) {
      await this.sleep(250);
      this.elements.progressFill.style.width = `${percent}%`;
      this.elements.progressText.textContent = `扫描中 ${percent}%...`;
    }
  }
  
  /**
   * 更新状态显示
   * @param {string} status - 状态类型 (ready/scanning)
   * @param {string} text - 状态文本
   */
  updateStatus(status, text) {
    this.elements.statusBadge.className = `status-badge status-${status}`;
    this.elements.statusBadge.textContent = text;
  }
  
  /**
   * 更新统计数据
   * @param {Object} summary - 摘要数据
   */
  updateStats(summary) {
    this.elements.statFiles.textContent = summary.total_code_units || 0;
    this.elements.statFindings.textContent = summary.total_findings || 0;
    this.elements.statRisk.textContent = (summary.risk_score || 0).toFixed(1);
    
    // 统计高危漏洞数量
    const highCount = this.currentFindings.filter(f => f.severity === 'ERROR').length;
    this.elements.statHigh.textContent = highCount;
  }
  
  /**
   * 清空之前的结果
   */
  clearResults() {
    this.currentFindings = [];
    this.currentEvidence = {};
    this.currentReport = { json: '', markdown: '', html: '' };
    
    this.elements.exportJsonBtn.disabled = true;
    this.elements.exportMarkdownBtn.disabled = true;
    this.elements.exportHtmlBtn.disabled = true;
    
    // 清空统计
    this.elements.statFiles.textContent = '0';
    this.elements.statFindings.textContent = '0';
    this.elements.statHigh.textContent = '0';
    this.elements.statRisk.textContent = '0.0';
    
    // 清空漏洞列表
    this.elements.findingsList.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>
        <h3>暂无漏洞数据</h3>
        <p>扫描进行中...</p>
      </div>
    `;
    
    // 清空详情
    this.elements.detailEmpty.classList.remove('hidden');
    this.elements.detailContent.classList.add('hidden');
    
    // 清空报告
    this.elements.reportContent.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path>
          <polyline points="14 2 14 8 20 8"></polyline>
          <line x1="16" y1="13" x2="8" y2="13"></line>
          <line x1="16" y1="17" x2="8" y2="17"></line>
          <polyline points="10 9 9 9 8 9"></polyline>
        </svg>
        <h3>报告生成中</h3>
        <p>请等待扫描完成</p>
      </div>
    `;
  }
  
  /**
   * 启用导出按钮
   */
  enableExportButtons() {
    this.elements.exportJsonBtn.disabled = false;
    this.elements.exportMarkdownBtn.disabled = false;
    this.elements.exportHtmlBtn.disabled = false;
  }
  
  /**
   * 渲染漏洞列表
   * @param {string} filter - 过滤条件 (all/high/medium/low)
   */
  renderFindings(filter) {
    let filtered = this.currentFindings;
    
    // 根据过滤条件筛选
    if (filter !== 'all') {
      const severityMap = {
        high: 'ERROR',
        medium: 'WARN',
        low: 'INFO'
      };
      filtered = this.currentFindings.filter(f => f.severity === severityMap[filter]);
    }
    
    // 处理空结果
    if (filtered.length === 0) {
      this.elements.findingsList.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
          </svg>
          <h3>暂无${filter === 'all' ? '' : filter}漏洞</h3>
          <p>${filter === 'all' ? '扫描完成，未发现漏洞' : '该级别暂无漏洞'}</p>
        </div>
      `;
      return;
    }
    
    // 渲染漏洞列表
    this.elements.findingsList.innerHTML = filtered.map((finding, index) => {
      const severityClass = this.getSeverityClass(finding.severity);
      const severityText = this.getSeverityText(finding.severity);
      
      return `
        <div class="finding-item ${severityClass}" data-index="${index}">
          <div class="finding-header">
            <span class="finding-title">${index + 1}. ${finding.type || '未知类型'}</span>
            <span class="finding-severity severity-${severityClass}">${severityText}</span>
          </div>
          <div class="finding-meta">
            <span>📁 ${finding.file_path || 'Unknown'}</span>
            <span>📝 行 ${finding.start_line || 0}</span>
            ${finding.cwe ? `<span>🔖 CWE-${finding.cwe}</span>` : ''}
          </div>
          <div class="finding-message">${finding.message || '无描述信息'}</div>
        </div>
      `;
    }).join('');
    
    // 添加点击事件
    document.querySelectorAll('.finding-item').forEach(item => {
      item.addEventListener('click', () => {
        // 更新选中状态
        document.querySelectorAll('.finding-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        
        // 显示详情
        const index = parseInt(item.dataset.index);
        this.showFindingDetail(filtered[index]);
      });
    });
  }
  
  /**
   * 获取严重程度样式类
   * @param {string} severity - 严重程度代码
   * @returns {string} - CSS类名
   */
  getSeverityClass(severity) {
    switch (severity) {
      case 'ERROR': return 'high';
      case 'WARN': return 'medium';
      case 'INFO': return 'low';
      default: return 'low';
    }
  }
  
  /**
   * 获取严重程度文本
   * @param {string} severity - 严重程度代码
   * @returns {string} - 显示文本
   */
  getSeverityText(severity) {
    switch (severity) {
      case 'ERROR': return '高危';
      case 'WARN': return '中危';
      case 'INFO': return '低危';
      default: return '未知';
    }
  }
  
  /**
   * 显示漏洞详情
   * @param {Object} finding - 漏洞对象
   */
  showFindingDetail(finding) {
    // 显示详情面板
    this.elements.detailEmpty.classList.add('hidden');
    this.elements.detailContent.classList.remove('hidden');
    
    // 获取严重程度显示文本
    const severityText = this.getSeverityEmoji(finding.severity);
    
    // 填充详情数据
    this.elements.detailType.textContent = finding.type || '-';
    this.elements.detailCwe.textContent = finding.cwe ? `CWE-${finding.cwe}` : '-';
    this.elements.detailRule.textContent = finding.rule_id || '-';
    this.elements.detailSeverity.textContent = severityText;
    this.elements.detailConfidence.textContent = finding.confidence || '-';
    this.elements.detailLocation.textContent = `${finding.file_path || '-'}:${finding.start_line || '-'}`;
    this.elements.detailMessage.textContent = finding.message || '无描述信息';
    
    // 获取代码片段
    this.elements.detailCode.textContent = this.getCodeSnippet(finding);
    
    // 获取修复建议
    this.elements.detailSuggestion.textContent = this.getSuggestion(finding);
  }
  
  /**
   * 获取严重程度表情符号
   * @param {string} severity - 严重程度代码
   * @returns {string} - 带表情的文本
   */
  getSeverityEmoji(severity) {
    switch (severity) {
      case 'ERROR': return '🔴 高危';
      case 'WARN': return '🟡 中危';
      case 'INFO': return '🟢 低危';
      default: return '⚪ 未知';
    }
  }
  
  /**
   * 获取代码片段
   * @param {Object} finding - 漏洞对象
   * @returns {string} - 代码片段
   */
  getCodeSnippet(finding) {
    const evidence = this.currentEvidence[finding.id];
    if (evidence && evidence.snippets && evidence.snippets.length > 0) {
      return evidence.snippets[0].content || '-';
    }
    if (finding.snippet) {
      return finding.snippet;
    }
    return '-';
  }
  
  /**
   * 获取修复建议
   * @param {Object} finding - 漏洞对象
   * @returns {string} - 修复建议
   */
  getSuggestion(finding) {
    let suggestion = finding.suggestion || '-';
    if (!suggestion) {
      const evidence = this.currentEvidence[finding.id];
      if (evidence && evidence.judge_decision) {
        suggestion = evidence.judge_decision.reason || '-';
      }
    }
    return suggestion;
  }
  
  /**
   * 渲染报告内容
   * @param {string} type - 报告类型 (json/markdown/html)
   */
  renderReport(type) {
    if (!this.currentReport[type]) {
      this.elements.reportContent.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10 9 9 9 8 9"></polyline>
          </svg>
          <h3>暂无${type.toUpperCase()}报告</h3>
          <p>扫描完成后可预览报告</p>
        </div>
      `;
      return;
    }
    
    switch (type) {
      case 'json':
        this.elements.reportContent.innerHTML = `<pre>${this.escapeHtml(this.currentReport.json)}</pre>`;
        break;
      case 'markdown':
        this.elements.reportContent.innerHTML = `<div class="markdown-preview">${this.markdownToHtml(this.currentReport.markdown)}</div>`;
        break;
      case 'html':
        this.elements.reportContent.innerHTML = `<div class="html-preview">${this.currentReport.html}</div>`;
        break;
    }
  }
  
  /**
   * 导出报告
   * @param {string} type - 报告类型
   * @param {string} filename - 文件名
   * @param {string} mimeType - MIME类型
   */
  exportReport(type, filename, mimeType) {
    if (!this.currentReport[type]) {
      this.showToast('暂无报告可导出', 'error');
      return;
    }
    
    const blob = new Blob([this.currentReport[type]], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    this.showToast(`报告已导出: ${filename}`, 'success');
  }
  
  /**
   * 显示Toast通知
   * @param {string} message - 消息内容
   * @param {string} type - 消息类型 (success/error)
   */
  showToast(message, type) {
    // 移除已存在的Toast
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
      existingToast.remove();
    }
    
    // 创建新Toast
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    // 3.5秒后自动移除
    setTimeout(() => {
      toast.remove();
    }, 3500);
  }
  
  /**
   * 辅助函数：延迟等待
   * @param {number} ms - 毫秒数
   * @returns {Promise}
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  /**
   * 辅助函数：HTML转义
   * @param {string} text - 原始文本
   * @returns {string} - 转义后的文本
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  /**
   * 辅助函数：Markdown转HTML
   * @param {string} markdown - Markdown文本
   * @returns {string} - HTML文本
   */
  markdownToHtml(markdown) {
    return markdown
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/^## (.*$)/gim, '<h2>$1</h2>')
      .replace(/^# (.*$)/gim, '<h1>$1</h1>')
      .replace(/\*\*(.*)\*\*/gim, '<strong>$1</strong>')
      .replace(/\*(.*)\*/gim, '<em>$1</em>')
      .replace(/`([^`]+)`/gim, '<code>$1</code>')
      .replace(/```(\w+)?\n([\s\S]*?)```/gim, '<pre><code>$2</code></pre>')
      .replace(/^- (.*$)/gim, '<li>$1</li>')
      .replace(/<\/li>\n<li>/gim, '</li><li>')
      .replace(/(<li>[\s\S]*?<\/li>)/gim, '<ul>$1</ul>')
      .replace(/^(\d+)\. (.*$)/gim, '<li>$2</li>')
      .replace(/\|([^|]+)\|/gim, (m, g) => {
        if (g.includes('---')) return m;
        return `<td>${g.trim()}</td>`;
      })
      .replace(/(\|.*\|)\n\|[-|]+\|/gim, '<table><tr>$1</tr>')
      .replace(/\|([^|]+)\|\n(?!\|[-|]+\|)/gim, '<tr><td>$1</td></tr>')
      .replace(/<\/tr>\n<table>/gim, '</tr></table><table>')
      .replace(/<table>([\s\S]*?)<\/table>/gim, (m, g) => {
        return `<table>${g}</table>`;
      })
      .replace(/^> (.*$)/gim, '<blockquote>$1</blockquote>')
      .replace(/\n/gim, '<br>');
  }
}

// 页面加载完成后初始化应用
document.addEventListener('DOMContentLoaded', () => {
  new VulnPatchApp();
});