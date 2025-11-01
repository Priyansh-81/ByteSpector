// === ByteSpector Forensics Frontend ===

// Flask backend API base URL
const API_BASE = "http://127.0.0.1:5000/api/forensic";

// DOM elements
const fileInput = document.getElementById("imageInput");
const uploadStatus = document.getElementById("uploadStatus");
const previewImage = document.getElementById("previewImage");
const startBtn = document.getElementById("startbtn");
const spinner = document.getElementById("loadingSpinner");
const clearBtn = document.getElementById("clearBtn");
const messageBox = document.getElementById("messageBox");
const downloadBtn = document.getElementById("downloadBtn");

let analyzedFileBlob = null;

// --- Helper: Check if file is image ---
function isImageFile(file) {
  return file && file.type.startsWith("image/");
}

// --- Show preview & upload status ---
fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) {
    if (isImageFile(file)) {
      const reader = new FileReader();
      reader.onload = (event) => {
        previewImage.src = event.target.result;
        previewImage.style.display = "block";
      };
      reader.readAsDataURL(file);
    } else {
      previewImage.style.display = "none";
    }

    uploadStatus.textContent = `${file.name} loaded successfully.`;
    uploadStatus.className = "status success";
  } else {
    previewImage.src = "";
    previewImage.style.display = "none";
    uploadStatus.textContent = "No file selected.";
    uploadStatus.className = "status";
  }
});

// --- Start button click ---
startBtn.addEventListener("click", async () => {
  const file = fileInput.files[0];
  if (!file) {
    alert("Please select a file first!");
    return;
  }

  const selectedOption = document.querySelector('input[name="forensics-option"]:checked').value;

  // LSB only works with image files
  if (!isImageFile(file) && selectedOption === "lsb") {
    alert("LSB Visualizer supports only image files (PNG/JPG).");
    return;
  }

  const formData = new FormData();
  formData.append("file", file); 

  spinner.classList.remove("hidden");
  uploadStatus.textContent = "🔍 Analyzing...";
  uploadStatus.className = "status loading";
  messageBox.value = "";
  downloadBtn.classList.add("hidden");

  try {
    let response;

    // --- LSB Visualizer ---
    if (selectedOption === "lsb") {
      response = await fetch(`${API_BASE}/lsb_visualize`, {
        method: "POST",
        body: formData
      });
      if (!response.ok) throw new Error("LSB visualization failed.");

      const blob = await response.blob();
      analyzedFileBlob = blob;
      const url = URL.createObjectURL(blob);
      previewImage.src = url;
      previewImage.style.display = "block";

      uploadStatus.textContent = "LSB visualization complete!";
      uploadStatus.className = "status success";
      downloadBtn.classList.remove("hidden");

      downloadBtn.onclick = () => {
        const a = document.createElement("a");
        a.href = url;
        a.download = "lsb_visualization.png";
        a.click();
        URL.revokeObjectURL(url);
      };

    // --- Magic Byte Analyzer ---
    } else if (selectedOption === "magic-byte") {
      response = await fetch(`${API_BASE}/magic_analyze`, {
        method: "POST",
        body: formData
      });

      const data = await response.json();
      if (data.error) throw new Error(data.error);

      messageBox.value =
        `File: ${file.name}\n\n` +
        `Detected File Type: ${data.detected_type || "Unknown"}\n` +
        `Magic Bytes: ${data.magic_bytes_hex || "N/A"}`;
      uploadStatus.textContent = "Magic byte analysis complete!";
      uploadStatus.className = "status success";

    // --- Metadata Extractor ---
    } else if (selectedOption === "metadata") {
      response = await fetch(`${API_BASE}/metadata_extract`, {
        method: "POST",
        body: formData
      });

      const data = await response.json();
      if (data.error) throw new Error(data.error);

      if (data.message) {
        messageBox.value = `File: ${file.name}\n\n${data.message}`;
      } else {
        messageBox.value =
          `File: ${file.name}\n\n` +
          JSON.stringify(data.metadata, null, 2);
      }

      uploadStatus.textContent = "Metadata extraction complete!";
      uploadStatus.className = "status success";
    }

  } catch (error) {
    uploadStatus.textContent = `${error.message}`;
    uploadStatus.className = "status error";
  } finally {
    spinner.classList.add("hidden");
  }
});

// --- Download analyzed image ---
downloadBtn.addEventListener("click", () => {
  if (!analyzedFileBlob) {
    alert("No analyzed file available to download yet!");
    return;
  }
  const url = URL.createObjectURL(analyzedFileBlob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "analysis_output.png";
  a.click();
  URL.revokeObjectURL(url);
});

// --- Clear button ---
clearBtn.addEventListener("click", () => {
  fileInput.value = "";
  previewImage.src = "";
  previewImage.style.display = "none";
  messageBox.value = "";
  uploadStatus.textContent = "No file selected.";
  uploadStatus.className = "status";
  downloadBtn.classList.add("hidden");
  analyzedFileBlob = null;
});