// === ByteSpector Steganography Frontend ===

// Flask backend API base URL
const API_BASE = "http://127.0.0.1:5000/api/stego";

// DOM elements
const imageInput = document.getElementById("imageInput");
const messageBox = document.getElementById("messageBox");
const startBtn = document.getElementById("startbtn");
const clearBtn = document.getElementById("clearBtn");

// === START BUTTON CLICK ===
startBtn.addEventListener("click", async () => {
  const file = imageInput.files[0];
  const selectedOption = document.querySelector('input[name="stego-option"]:checked').value;

  if (!file) {
    alert("Please select an image file first!");
    return;
  }

  if (selectedOption === "embed") {
    const secret = messageBox.value.trim();
    if (!secret) {
      alert("Please enter a secret message to embed!");
      return;
    }

    const formData = new FormData();
    formData.append("image", file);
    formData.append("secret", secret);

    try {
      const response = await fetch(`${API_BASE}/embed`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const err = await response.json();
        alert("Error: " + (err.error || "Embedding failed."));
        return;
      }

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "stego_output.png";
      a.click();
      URL.revokeObjectURL(url);

      alert("✅ Message embedded successfully! File downloaded as stego_output.png");
    } catch (error) {
      alert("❌ Connection error: " + error.message);
    }

  } else if (selectedOption === "extract") {
    const formData = new FormData();
    formData.append("image", file);

    try {
      const response = await fetch(`${API_BASE}/extract`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      if (data.error) {
        alert("Error: " + data.error);
        return;
      }

      messageBox.value = data.secret || "(No hidden message found)";
    } catch (error) {
      alert("❌ Connection error: " + error.message);
    }
  }
});

// === CLEAR BUTTON ===
clearBtn.addEventListener("click", () => {
  imageInput.value = "";
  messageBox.value = "";
});