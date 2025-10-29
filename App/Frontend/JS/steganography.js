document.addEventListener("DOMContentLoaded", () => {
  // --- DOM Elements ---
  const toolButtons = document.querySelectorAll(".tool-btn");
  const fileInput = document.getElementById("imageInput");
  const messageBox = document.getElementById("messageBox");
  const embedBtn = document.getElementById("embedBtn");
  const extractBtn = document.getElementById("extractBtn");
  const clearBtn = document.getElementById("clearBtn");

  // --- State ---
  let currentTool = "Embed Message"; // Default tool
  const API_BASE_URL = "http://127.0.0.1:5000/api/steganography";

  // --- Functions ---

  // Highlight active tool button
  function setActiveTool(e) {
    toolButtons.forEach(btn => btn.classList.remove("active"));
    e.target.classList.add("active");
    currentTool = e.target.textContent;
  }

  // Clear fields
  function clearFields() {
    fileInput.value = "";
    messageBox.value = "";
  }

  // Handle Embed or Extract API
  async function handleSteganography(action) {
    const file = fileInput.files[0];
    let endpoint = "";
    let formData = new FormData();

    if (!file) {
      alert("Please upload an image file first!");
      return;
    }

    if (action === "embed") {
      if (!messageBox.value.trim()) {
        alert("Please enter a message to embed!");
        return;
      }
      endpoint = `${API_BASE_URL}/embed`;
      formData.append("image", file);
      formData.append("message", messageBox.value);

    } else if (action === "extract") {
      endpoint = `${API_BASE_URL}/extract`;
      formData.append("image", file);
    }

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        body: formData
      });

      const data = await response.json();

      if (!response.ok) {
        messageBox.value = `Error: ${data.error || "Unknown server error"}`;
      } else {
        messageBox.value =
          action === "extract"
            ? data.message
            : "✅ Message successfully embedded in image!";
      }

    } catch (error) {
      console.error("Fetch error:", error);
      messageBox.value = "Error: Server did not respond.";
    }
  }

  // --- Event Listeners ---
  toolButtons.forEach(button => {
    button.addEventListener("click", setActiveTool);
  });

  embedBtn.addEventListener("click", () => handleSteganography("embed"));
  extractBtn.addEventListener("click", () => handleSteganography("extract"));
  clearBtn.addEventListener("click", clearFields);

  // Activate first tool by default
  if (toolButtons.length > 0) {
    toolButtons[0].classList.add("active");
  }
});
