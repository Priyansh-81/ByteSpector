document.addEventListener("DOMContentLoaded", () => {
  // --- DOM Elements ---
  const inputText = document.getElementById("inputText");
  const outputText = document.getElementById("outputText");
  const keyInput = document.getElementById("key");
  const encryptBtn = document.getElementById("encryptBtn");
  const decryptBtn = document.getElementById("decryptBtn");
  const clearBtn = document.getElementById("clearBtn");


  const API_BASE_URL = "http://127.0.0.1:5000/api";

  // --- Get Selected Tool ---
  function getSelectedTool() {
    const selected = document.querySelector('input[name="crypto-option"]:checked');
    return selected ? selected.value.toLowerCase() : null;
  }

  // --- Clear Fields ---
  function clearFields() {
    inputText.value = "";
    outputText.value = "";
    keyInput.value = "";
  }

  // --- Handle Encrypt/Decrypt API Calls ---
  async function handleApiCall(action) {
    const text = inputText.value.trim();
    const key = keyInput.value.trim();
    const tool = getSelectedTool();

    if (!text) {
      outputText.value = "Error: Enter text.";
      return;
    }

    if (
      !["b64", "base64", "hex", "sha256", "md5", "xor", "rsa", "rabin", "ecc"].includes(tool) &&
      !key
    ) {
      outputText.value = "Error: Enter key.";
      return;
    }

    let endpoint = "";
    let payload = {};
    const textKey = action === "encrypt" ? "pt" : "ct";
    const resultKey = action === "encrypt" ? "ct" : "pt";

    switch (tool) {
      // --- Symmetric ---
      case "ceaser":
        endpoint = `${API_BASE_URL}/symmetric/Ceaser/${action}`;
        payload = { [textKey]: text, key: parseInt(key) };
        break;
      case "multiplicative":
        endpoint = `${API_BASE_URL}/symmetric/Multiplicative/${action}`;
        payload = { [textKey]: text, key: parseInt(key) };
        break;
      case "affine":
        const parts = key.split(",").map(k => parseInt(k.trim()));
        if (parts.length !== 2 || parts.some(isNaN)) {
          outputText.value = "Error: Enter key as 'a,b'";
          return;
        }
        endpoint = `${API_BASE_URL}/symmetric/Affine/${action}`;
        payload = { [textKey]: text, a: parts[0], b: parts[1] };
        break;
      case "autokey":
        endpoint = `${API_BASE_URL}/symmetric/Autokey/${action}`;
        payload = { [textKey]: text, key: key };
        break;
      case "vigenere":
        endpoint = `${API_BASE_URL}/symmetric/Vigenere/${action}`;
        payload = { [textKey]: text, key: key };
        break;
      case "playfair":
        endpoint = `${API_BASE_URL}/symmetric/Playfair/${action}`;
        payload = { [textKey]: text, key: key };
        break;
      case "hill":
        const nums = key.split(",").map(k => parseInt(k.trim()));
        if (nums.length !== 4 || nums.some(isNaN)) {
          outputText.value = "Error: Enter key as 4 comma-separated numbers";
          return;
        }
        endpoint = `${API_BASE_URL}/symmetric/Hill/${action}`;
        payload = { [textKey]: text, key: nums };
        break;
      case "des":
        endpoint = `${API_BASE_URL}/symmetric/DES/${action}`;
        payload = { [textKey]: text, key: key };
        break;
      case "aes":
        endpoint = `${API_BASE_URL}/symmetric/AES/${action}`;
        payload = { [textKey]: text, key: key };
        break;

      // --- Transform ---
      case "b64":
      case "base64":
        endpoint = `${API_BASE_URL}/transform/Base64/${action}`;
        payload = { [textKey]: text };
        break;
      case "hex":
        endpoint = `${API_BASE_URL}/transform/Hex/${action}`;
        payload = { [textKey]: text };
        break;
      case "sha256":
        endpoint = `${API_BASE_URL}/transform/HashSHA256/encrypt`;
        payload = { [textKey]: text };
        break;
      case "md5":
        endpoint = `${API_BASE_URL}/transform/HashMD5/encrypt`;
        payload = { [textKey]: text };
        break;

      default:
        outputText.value = "Error: Unsupported cipher.";
        return;
    }

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (!res.ok) outputText.value = `Error: ${data.error || "Unknown error"}`;
      else outputText.value = data[resultKey] || data.ct || data.pt || data.result || "No output.";
    } catch (err) {
      outputText.value = "Server error. Check Python backend.";
    }
  }

  // --- Event Listeners ---
  encryptBtn.addEventListener("click", () => handleApiCall("encrypt"));
  decryptBtn.addEventListener("click", () => handleApiCall("decrypt"));
  clearBtn.addEventListener("click", clearFields);
  generateKeyBtn.addEventListener("click", generateKeys);
});