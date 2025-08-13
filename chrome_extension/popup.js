const apiURL = "http://127.0.0.1:5000/predict_email";

document.getElementById('scanBtn').addEventListener('click', async () => {
  const fileInput = document.getElementById('emailFile');
  const resultDiv = document.getElementById('result');

  if (!fileInput.files.length) {
    resultDiv.innerHTML = "Please select a .eml file.";
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  resultDiv.innerHTML = "Scanning…";

  try {
    const res = await fetch(apiURL, { method: "POST", body: formData });
    const data = await res.json();

    if (!res.ok) {
      resultDiv.innerHTML = `Error: ${data.error || "Unknown error"}`;
      return;
    }

    const reasonsHTML = (data.reasons || [])
      .map(r => `<li><b>${r.feature}</b>: value=${r.value}, weight=${r.weight.toFixed(4)}</li>`)
      .join("");

    resultDiv.innerHTML = `
      <b>Prediction:</b> ${data.prediction}<br/>
      <b>Confidence:</b> ${data.confidence}<br/>
      <b>Top reasons:</b>
      <ul>${reasonsHTML}</ul>
    `;
  } catch (e) {
    resultDiv.innerHTML = "Failed to reach the API. Is it running?";
  }
});
