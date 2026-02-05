const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const statusText = document.getElementById("statusText");
const summaryOutput = document.getElementById("summaryOutput");
const detailOutput = document.getElementById("detailOutput");

const backendUrlInput = document.getElementById("backendUrl");
const modeSelect = document.getElementById("mode");
const logTypeInput = document.getElementById("logType");
const fileInput = document.getElementById("fileInput");
const logText = document.getElementById("logText");

function setStatus(message, isError = false) {
  statusText.textContent = message;
  statusText.style.color = isError ? "#ff4d6d" : "#b4bdd9";
}

function renderResult(data) {
  summaryOutput.textContent = data.report || "No report generated.";
  detailOutput.textContent = JSON.stringify(
    {
      id: data.id,
      mode: data.mode,
      detected_types: data.detected_types,
      stats: data.stats,
      chunk_count: data.chunk_count,
      chunk_summaries: data.chunk_summaries,
    },
    null,
    2
  );
}

async function analyze() {
  const backendUrl = backendUrlInput.value.replace(/\/$/, "");
  if (!backendUrl) {
    setStatus("Enter a backend URL.", true);
    return;
  }

  const mode = modeSelect.value;
  const logType = logTypeInput.value.trim();
  const file = fileInput.files[0];
  const text = logText.value.trim();

  setStatus("Analyzing logs...");
  analyzeBtn.disabled = true;

  try {
    let response;
    if (file) {
      const formData = new FormData();
      formData.append("file", file);
      if (logType) formData.append("log_type", logType);
      formData.append("mode", mode);
      response = await fetch(`${backendUrl}/analyze-file`, {
        method: "POST",
        body: formData,
      });
    } else {
      if (!text) {
        setStatus("Provide a file or paste logs.", true);
        analyzeBtn.disabled = false;
        return;
      }
      response = await fetch(`${backendUrl}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, log_type: logType || null, mode }),
      });
    }

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(errText || "Request failed");
    }
    const data = await response.json();
    renderResult(data);
    setStatus("Analysis complete.");
  } catch (error) {
    setStatus(`Error: ${error.message}`, true);
  } finally {
    analyzeBtn.disabled = false;
  }
}

analyzeBtn.addEventListener("click", analyze);
clearBtn.addEventListener("click", () => {
  logText.value = "";
  fileInput.value = "";
  summaryOutput.textContent = "No analysis yet.";
  detailOutput.textContent = "Upload logs to see details.";
  setStatus("Ready.");
});
