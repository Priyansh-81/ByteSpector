document.addEventListener("DOMContentLoaded", () => {
  const toolButtons = document.querySelectorAll(".tool-btn");
  const fileInput = document.getElementById("fileInput");
  const outputArea = document.getElementById("output");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const clearBtn = document.getElementById("clearBtn");

  let currentTool = "LSB Visualizer";

  // Highlight active tool
  toolButtons.forEach(button => {
    button.addEventListener("click", () => {
      toolButtons.forEach(btn => btn.classList.remove("active"));
      button.classList.add("active");
      currentTool = button.textContent;
      outputArea.value = `Selected Tool: ${currentTool}`;
    });
  });

  // Analyze button click
  analyzeBtn.addEventListener("click", () => {
    if (!fileInput.files.length) {
      outputArea.value = "Please upload a file first!";
      return;
    }
    const file = fileInput.files[0];
    outputArea.value = `Analyzing "${file.name}" using ${currentTool}...\n\n(Result will be displayed here after backend connection)`;
  });

  // Clear button click
  clearBtn.addEventListener("click", () => {
    fileInput.value = "";
    outputArea.value = "";
  });

  // Set first tool active on load
  if (toolButtons.length > 0) {
    toolButtons[0].classList.add("active");
  }
});
