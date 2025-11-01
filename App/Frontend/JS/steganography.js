// === ByteSpector Steganography Frontend ===

// Flask backend API base URL
const API_BASE = "http://127.0.0.1:5000/api/stego";

// DOM elements
const imageInput = document.getElementById("imageInput");
const uploadStatus = document.getElementById("uploadStatus");
const previewImage = document.getElementById("previewImage");
const startBtn = document.getElementById("startbtn");
const spinner = document.getElementById("loadingSpinner");
const clearBtn = document.getElementById("clearBtn");
const messageBox = document.getElementById("messageBox");
const downloadBtn = document.getElementById("downloadBtn");

let stegoImageBlob = null;

// --- Show preview & upload status ---
imageInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = function (event) {
      previewImage.src = event.target.result;
      previewImage.style.display = "block";
      uploadStatus.textContent = `✅ ${file.name} loaded successfully.`;
      uploadStatus.className = "status success";
    };
    reader.readAsDataURL(file);
  } else {
    previewImage.src = "";
    previewImage.style.display = "none";
    uploadStatus.textContent = "No file selected.";
    uploadStatus.className = "status";
  }
});

// --- Start process ---
startBtn.addEventListener("click", async () => {
  const file = imageInput.files[0];
  const option = document.querySelector('input[name="stego-option"]:checked').value;
  if (!file) return alert("Please select an image first!");

  spinner.classList.remove("hidden");
  uploadStatus.textContent = "Processing...";
  uploadStatus.className = "status loading";

  if (option === "embed") {
    const secret = messageBox.value.trim();
    if (!secret) {
      spinner.classList.add("hidden");
      return alert("Please enter a secret message!");
    }

    const formData = new FormData();
    formData.append("image", file);
    formData.append("secret", secret);

    try {
      const response = await fetch(`${API_BASE}/embed`, { method: "POST", body: formData });
      if (!response.ok) throw new Error("Embedding failed.");

      const blob = await response.blob();
      stegoImageBlob = blob;
      const url = URL.createObjectURL(blob);
      previewImage.src = url;

      uploadStatus.textContent = "✅ Message embedded successfully!";
      uploadStatus.className = "status success";
      spinner.classList.add("hidden");
      downloadBtn.classList.remove("hidden");
    } catch (err) {
      spinner.classList.add("hidden");
      uploadStatus.textContent = "❌ " + err.message;
      uploadStatus.className = "status error";
    }

  } else if (option === "extract") {
    const formData = new FormData();
    formData.append("image", file);

    try {
      const response = await fetch(`${API_BASE}/extract`, { method: "POST", body: formData });
      const data = await response.json();
      if (data.error) throw new Error(data.error);

      messageBox.value = data.secret || "(No hidden message found)";
      uploadStatus.textContent = "Message extracted successfully!";
      uploadStatus.className = "status success";
    } catch (err) {
      uploadStatus.textContent = "" + err.message;
      uploadStatus.className = "status error";
    } finally {
      spinner.classList.add("hidden");
    }
  }
});

// --- Download stego image ---
downloadBtn.addEventListener("click", () => {
  if (!stegoImageBlob) {
    alert("No stego image available to download yet!");
    return;
  }
  const url = URL.createObjectURL(stegoImageBlob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "stego_output.png";
  a.click();
  URL.revokeObjectURL(url);
});

// --- Clear ---
clearBtn.addEventListener("click", () => {
  imageInput.value = "";
  previewImage.src = "";
  messageBox.value = "";
  uploadStatus.textContent = "No file selected.";
  uploadStatus.className = "status";
  downloadBtn.classList.add("hidden");
  stegoImageBlob = null;
});