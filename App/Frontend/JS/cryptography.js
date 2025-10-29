document.addEventListener("DOMContentLoaded", () => {
  // --- DOM Elements ---
  const inputText = document.getElementById("inputText");
  const outputText = document.getElementById("outputText");
  const keyInput = document.getElementById("key");
  const encryptBtn = document.getElementById("encryptBtn");
  const decryptBtn = document.getElementById("decryptBtn");
  const clearBtn = document.getElementById("clearBtn");
  const cryptoOptions = document.querySelectorAll('input[name="crypto-option"]');

  const API_BASE_URL = "http://127.0.0.1:5000/api/symmetric";

  // Get selected tool
  function getSelectedTool() {
    const selected = document.querySelector('input[name="crypto-option"]:checked');
    return selected ? selected.value : null;
  }

  // Clear the fields
  function clearFields() {
    inputText.value = "";
    outputText.value = "";
    keyInput.value = "";
  }

  // Handle API request
  async function handleApiCall(action) {
    const text = inputText.value.trim();
    const key = keyInput.value.trim();
    const tool = getSelectedTool();

    if (!text) {
      outputText.value = "Error: Enter text.";
      return;
    }
    if (!key) {
      outputText.value = "Error: Enter key.";
      return;
    }

    let endpoint = "";
    let payload = {};
    const textKey = action === "encrypt" ? "pt" : "ct";
    const resultKey = action === "encrypt" ? "ct" : "pt";

    if (tool === "caesar") {
      endpoint = `${API_BASE_URL}/Ceaser/${action}`;
      payload = { [textKey]: text, key: parseInt(key) };
    } else {
      outputText.value = "Error: Tool not supported yet.";
      return;
    }

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok) {
        outputText.value = `Error: ${data.error}`;
      } else {
        outputText.value = data[resultKey];
      }
    } catch (error) {
      outputText.value = "Server error. Check Python server.";
      console.error(error);
    }
  }

  // Event listeners
  encryptBtn.addEventListener("click", () => handleApiCall("encrypt"));
  decryptBtn.addEventListener("click", () => handleApiCall("decrypt"));
  clearBtn.addEventListener("click", clearFields);
});
