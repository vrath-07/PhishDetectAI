const apiURL = "http://127.0.0.1:5000/predict_email";

const fileInput = document.getElementById("emailFile");
const dropZone = document.getElementById("dropZone");
const scanBtn = document.getElementById("scanBtn");
const resultDiv = document.getElementById("result");

// Open file dialog when clicking drop zone
dropZone.addEventListener("click", () => fileInput.click());

// Show selected file name
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) {
    dropZone.querySelector("p").textContent = `📂 ${fileInput.files[0].name} selected`;
  }
});

// Handle drag & drop
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});
dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("dragover");
});
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    dropZone.querySelector("p").textContent = `📂 ${fileInput.files[0].name} selected`;
  }
});

// Scan button
scanBtn.addEventListener("click", async () => {
  if (!fileInput.files.length) {
    resultDiv.className = "warning";
    resultDiv.innerHTML = "⚠️ Please select or drop a .eml file.";
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  resultDiv.className = "neutral";
  resultDiv.innerHTML = "⏳ Scanning your email…";

  try {
    const res = await fetch(apiURL, { method: "POST", body: formData });
    const data = await res.json();

    if (!res.ok) {
      resultDiv.className = "error";
      resultDiv.innerHTML = `❌ Error: ${data.error || "Unknown error"}`;
      return;
    }

    // Decide colors/icons
    const isPhishing = data.prediction === "Phishing";
    const statusClass = isPhishing ? "error" : "safe";
    const statusIcon = isPhishing ? "🚨" : "✅";

    const confidencePercent = (data.confidence * 100).toFixed(2);
    const riskBarColor = isPhishing ? "#ff4d4d" : "#4CAF50";

    const reasonsHTML = (data.reasons || [])
      .map(r => `<li><b>${r.feature.replace(/_/g, " ")}</b>: ${r.value}</li>`)
      .join("");

    resultDiv.className = statusClass;
    resultDiv.innerHTML = `
      <p><b>${statusIcon} Prediction:</b> ${data.prediction}</p>
      <p><b>Confidence:</b> ${confidencePercent}%</p>
      <div class="risk-bar">
        <div class="risk-fill" style="width:${confidencePercent}%; background:${riskBarColor}"></div>
      </div>
      <p><b>Why:</b></p>
      <ul>${reasonsHTML}</ul>
    `;
  } catch (e) {
    resultDiv.className = "error";
    resultDiv.innerHTML = "❌ Failed to reach the API. Please make sure it is running.";
  }
});
