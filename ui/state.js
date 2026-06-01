/**
 * State Module - Application state management
 *
 * Provides centralized state management for VulnPatch UI.
 * Team Member Assignment: Member 4 (API, UI & Report)
 */

const VulnPatchState = (function() {
  // Application state
  let running = false;
  let lastAnalysisResult = null;
  let selectedFindingId = null;
  let selectedLanguage = "all";
  let inputType = "code";
  let jobProgress = { status: "idle", stage: "", progress: 0, message: "" };

  /**
   * Check if a scan is running
   * @returns {boolean}
   */
  function isRunning() {
    return running;
  }

  /**
   * Set running state
   * @param {boolean} value
   */
  function setRunning(value) {
    running = value;
  }

  /**
   * Get last analysis result
   * @returns {object|null}
   */
  function getLastResult() {
    return lastAnalysisResult;
  }

  /**
   * Set last analysis result
   * @param {object} result
   */
  function setLastResult(result) {
    lastAnalysisResult = result;
  }

  /**
   * Get selected finding ID
   * @returns {string|null}
   */
  function getSelectedFindingId() {
    return selectedFindingId;
  }

  /**
   * Set selected finding ID
   * @param {string|null} id
   */
  function setSelectedFindingId(id) {
    selectedFindingId = id;
  }

  /**
   * Get selected language filter
   * @returns {string}
   */
  function getSelectedLanguage() {
    return selectedLanguage;
  }

  /**
   * Set selected language filter
   * @param {string} lang
   */
  function setSelectedLanguage(lang) {
    selectedLanguage = lang;
  }

  /**
   * Get input type
   * @returns {string}
   */
  function getInputType() {
    return inputType;
  }

  /**
   * Set input type
   * @param {string} type
   */
  function setInputType(type) {
    inputType = type;
  }

  /**
   * Get job progress
   * @returns {object}
   */
  function getJobProgress() {
    return jobProgress;
  }

  /**
   * Set job progress
   * @param {object} progress
   */
  function setJobProgress(progress) {
    jobProgress = progress;
  }

  /**
   * Reset all state
   */
  function reset() {
    running = false;
    lastAnalysisResult = null;
    selectedFindingId = null;
    selectedLanguage = "all";
    inputType = "code";
    jobProgress = { status: "idle", stage: "", progress: 0, message: "" };
  }

  return {
    isRunning,
    setRunning,
    getLastResult,
    setLastResult,
    getSelectedFindingId,
    setSelectedFindingId,
    getSelectedLanguage,
    setSelectedLanguage,
    getInputType,
    setInputType,
    getJobProgress,
    setJobProgress,
    reset
  };
})();