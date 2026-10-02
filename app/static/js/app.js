// Global App State
let currentAnalysis = null;
let currentDetection = null;

// Screen Switcher
function showScreen(screenId) {
  const screens = ["screen-upload", "screen-results", "screen-detail", "screen-report"];
  screens.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      if (id === screenId) {
        el.classList.add("active");
      } else {
        el.classList.remove("active");
      }
    }
  });

  if (screenId === "screen-upload") {
    loadRecentLogs();
  }
}

// Helpers
function getSeverityBadge(severity) {
  const sev = (severity || "low").toLowerCase();
  let cssClass = "sev-info";
  if (sev === "critical") cssClass = "sev-critical";
  else if (sev === "high") cssClass = "sev-high";
  else if (sev === "medium") cssClass = "sev-medium";
  else if (sev === "low") cssClass = "sev-low";

  return `<span class="severity-badge ${cssClass}">${sev.toUpperCase()}</span>`;
}

function getMethodBadge(method) {
  const m = (method || "rule").toLowerCase();
  return `<span class="method-badge method-${m}">${m.toUpperCase()}</span>`;
}

function formatDate(isoStr) {
  if (!isoStr) return "-";
  try {
    const d = new Date(isoStr);
    return d.toLocaleString();
  } catch (e) {
    return isoStr;
  }
}

function showLoading(msg = "Analyzing Log File...") {
  const overlay = document.getElementById("loading-overlay");
  const text = document.getElementById("loading-text");
  if (text) text.innerText = msg;
  if (overlay) overlay.style.display = "flex";
}

function hideLoading() {
  const overlay = document.getElementById("loading-overlay");
  if (overlay) overlay.style.display = "none";
}

// API Calls & Actions
async function loadRecentLogs() {
  const tbody = document.getElementById("recent-logs-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/logs");
    if (!res.ok) throw new Error("Failed to load recent logs");
    const logs = await res.json();

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No logs uploaded yet. Upload a log to begin!</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(log => `
      <tr onclick="loadAnalysisById(${log.id})">
        <td style="font-weight: 600; color: var(--accent-cyan);">${escapeHtml(log.original_filename)}</td>
        <td><span style="text-transform: uppercase; font-size: 0.8rem; background: var(--bg-card); padding: 0.2rem 0.5rem; border-radius: 4px;">${escapeHtml(log.log_type)}</span></td>
        <td>${formatDate(log.uploaded_at)}</td>
        <td>${getSeverityBadge(log.severity)}</td>
        <td><span style="font-weight: 700;">${log.detection_count}</span> findings</td>
        <td><button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); loadAnalysisById(${log.id})">View →</button></td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--severity-critical);">${err.message}</td></tr>`;
  }
}

async function uploadFile(file) {
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  showLoading(`Analyzing ${file.name}...`);
  try {
    const res = await fetch("/api/upload", {
      method: "POST",
      body: formData
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || "Error during log analysis");
    }

    const data = await res.json();
    currentAnalysis = data;
    renderResults(data);
    showScreen("screen-results");
  } catch (err) {
    alert("Upload failed: " + err.message);
  } finally {
    hideLoading();
  }
}

async function uploadSample(sampleName) {
  showLoading(`Loading sample '${sampleName}'...`);
  try {
    // Read the sample file from static/sample endpoint or fetch directly
    const res = await fetch(`/sample/${sampleName}`);
    if (!res.ok) {
      // Fallback: try fetching from raw sample
      throw new Error("Sample file not available via web. You can upload it from sample_logs/ folder.");
    }
    const blob = await res.blob();
    const file = new File([blob], sampleName, { type: "text/plain" });
    await uploadFile(file);
  } catch (err) {
    alert(err.message);
    hideLoading();
  }
}

async function loadAnalysisById(logFileId) {
  showLoading("Fetching investigation report...");
  try {
    const res = await fetch(`/api/analysis/${logFileId}`);
    if (!res.ok) throw new Error("Could not retrieve analysis");
    const data = await res.json();
    currentAnalysis = data;
    renderResults(data);
    showScreen("screen-results");
  } catch (err) {
    alert("Failed to load report: " + err.message);
  } finally {
    hideLoading();
  }
}

// Screen 2 Render
function renderResults(analysis) {
  // Metadata
  document.getElementById("res-filename").innerText = analysis.original_filename;
  document.getElementById("res-meta-line").innerText = 
    `Type: ${analysis.log_type.toUpperCase()} | Uploaded: ${formatDate(analysis.uploaded_at)} | Total Events: ${analysis.total_events}`;
  
  // Severity badge
  const sevBadgeContainer = document.getElementById("res-severity-badge");
  const overallSev = analysis.report.severity;
  sevBadgeContainer.className = `severity-badge ${getSeverityClass(overallSev)}`;
  sevBadgeContainer.innerText = overallSev.toUpperCase();

  // Summary Box
  document.getElementById("res-summary-text").innerText = analysis.report.summary;
  const modeBadge = document.getElementById("res-llm-mode");
  modeBadge.innerText = analysis.report.mode === "real" ? "Ollama LLM" : "Mock AI Mode";
  modeBadge.style.borderColor = analysis.report.mode === "real" ? "#34d399" : "var(--accent-blue)";

  // Tactics
  const tacticsContainer = document.getElementById("res-tactics-container");
  tacticsContainer.innerHTML = (analysis.report.tactics || []).map(t => 
    `<span class="tactic-pill">${escapeHtml(t)}</span>`
  ).join("");

  // Detections Table
  const tbody = document.getElementById("detections-tbody");
  document.getElementById("res-detection-count").innerText = `${analysis.detections.length} Finding(s)`;

  if (!analysis.detections || analysis.detections.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">No security threats or anomalies detected. System baseline is clean.</td></tr>`;
    return;
  }

  tbody.innerHTML = analysis.detections.map(det => `
    <tr onclick="loadDetectionDetail(${det.id})">
      <td style="font-weight: 700; color: #f8fafc;">${escapeHtml(det.name)}</td>
      <td>${getMethodBadge(det.method)}</td>
      <td>${getSeverityBadge(det.severity)}</td>
      <td><span class="tactic-pill" style="font-size: 0.72rem;">${escapeHtml(det.mitre_tactic)}</span></td>
      <td style="color: var(--text-muted); max-width: 400px;">${escapeHtml(det.description)}</td>
      <td style="font-weight: 600; color: var(--accent-cyan);">${det.indices.length}</td>
      <td><button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); loadDetectionDetail(${det.id})">Detail →</button></td>
    </tr>
  `).join("");

  // Prepare full report
  renderFullReport();
}

function getSeverityClass(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "sev-critical";
  if (s === "high") return "sev-high";
  if (s === "medium") return "sev-medium";
  if (s === "low") return "sev-low";
  return "sev-info";
}

// Screen 3: Detection Detail
async function loadDetectionDetail(detectionId) {
  showLoading("Fetching raw event lines...");
  try {
    const res = await fetch(`/api/detection/${detectionId}/detail`);
    if (!res.ok) throw new Error("Could not load detection detail");
    const det = await res.json();
    currentDetection = det;

    document.getElementById("det-title").innerText = det.name;
    const sevBadge = document.getElementById("det-severity-badge");
    sevBadge.className = `severity-badge ${getSeverityClass(det.severity)}`;
    sevBadge.innerText = det.severity.toUpperCase();

    const methBadge = document.getElementById("det-method-badge");
    methBadge.className = `method-badge method-${det.method.toLowerCase()}`;
    methBadge.innerText = det.method.toUpperCase();

    document.getElementById("det-tactic").innerText = `MITRE ATT&CK Tactic: ${det.mitre_tactic}`;
    document.getElementById("det-description").innerText = det.description;
    document.getElementById("det-lines-count").innerText = `${det.raw_lines.length} triggered line(s)`;

    // Render raw log viewer
    const linesViewer = document.getElementById("det-raw-lines");
    if (!det.raw_lines || det.raw_lines.length === 0) {
      linesViewer.innerHTML = `<div style="color: var(--text-dim); padding: 1rem;">No raw log lines mapped.</div>`;
    } else {
      linesViewer.innerHTML = det.raw_lines.map((line, idx) => {
        const lineNum = det.indices && det.indices[idx] !== undefined ? det.indices[idx] + 1 : idx + 1;
        return `
          <div class="code-line code-line-highlight">
            <span class="code-line-num">L${lineNum}</span>
            <span class="code-line-text">${escapeHtml(line)}</span>
          </div>
        `;
      }).join("");
    }

    showScreen("screen-detail");
  } catch (err) {
    alert("Error loading detection details: " + err.message);
  } finally {
    hideLoading();
  }
}

// Screen 4: Full Report
function renderFullReport() {
  if (!currentAnalysis) return;
  const rep = currentAnalysis.report;

  document.getElementById("rep-filename").innerText = currentAnalysis.original_filename;
  document.getElementById("rep-logtype").innerText = currentAnalysis.log_type;
  document.getElementById("rep-mode").innerText = rep.mode === "real" ? "Ollama Local LLM" : "Mock AI Generator";
  document.getElementById("rep-total-findings").innerText = currentAnalysis.detections.length;
  document.getElementById("rep-header-meta").innerText = `Generated at: ${formatDate(rep.generated_at)}`;

  const repSevBadge = document.getElementById("rep-severity-badge");
  repSevBadge.className = `severity-badge ${getSeverityClass(rep.severity)}`;
  repSevBadge.innerText = rep.severity.toUpperCase();

  document.getElementById("rep-summary-text").innerText = rep.summary;

  const tacticsList = document.getElementById("rep-tactics-list");
  tacticsList.innerHTML = (rep.tactics || []).map(t => 
    `<span class="tactic-pill" style="font-size: 0.85rem; padding: 0.35rem 0.75rem;">${escapeHtml(t)}</span>`
  ).join("");
}

function escapeHtml(text) {
  if (text === null || text === undefined) return "";
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

// Drag & Drop & Input Listeners
document.addEventListener("DOMContentLoaded", () => {
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");

  if (dropZone && fileInput) {
    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        uploadFile(e.target.files[0]);
      }
    });

    ["dragenter", "dragover"].forEach(name => {
      dropZone.addEventListener(name, (e) => {
        e.preventDefault();
        dropZone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach(name => {
      dropZone.addEventListener(name, (e) => {
        e.preventDefault();
        dropZone.classList.remove("dragover");
      });
    });

    dropZone.addEventListener("drop", (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        uploadFile(e.dataTransfer.files[0]);
      }
    });
  }

  // Initial load
  loadRecentLogs();
});
