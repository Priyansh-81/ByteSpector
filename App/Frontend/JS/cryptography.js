document.addEventListener("DOMContentLoaded", () => {
  // --- DOM Elements ---
  const toolButtons = document.querySelectorAll(".tool-btn");
  const inputText = document.getElementById("inputText");
  const outputText = document.getElementById("outputText");
  const keyInput = document.getElementById("key");
  const encryptBtn = document.getElementById("encryptBtn");
  const decryptBtn = document.getElementById("decryptBtn");
  const clearBtn = document.getElementById("clearBtn");

  // --- State ---
  let currentTool = "Ceaser Cipher"; // Default tool
  // This URL assumes your Python server is running on localhost port 5000
  const API_BASE_URL = "http://127.0.0.1:5000/api/symmetric"; 

  // --- Functions ---

  /**
   * Sets the active tool and updates the UI
   * @param {Event} e - The click event from the tool button
   */
  function setActiveTool(e) {
    // Remove 'active' class from all buttons
    toolButtons.forEach(btn => btn.classList.remove("active"));
    
    // Add 'active' class to the clicked button
    const clickedButton = e.target;
    clickedButton.classList.add("active");
    
    // Update the current tool state
    currentTool = clickedButton.textContent;
    
    // Update key placeholder
    updateKeyPlaceholder(currentTool);
  }

  /**
   * Updates the key field's placeholder text based on the selected tool
   * @param {string} toolName - The name of the currently selected tool
   */
  function updateKeyPlaceholder(toolName) {
    switch (toolName) {
      case "Ceaser Cipher":
      case "Multiplicative Cipher":
        keyInput.placeholder = "Enter the numeric key...";
        break;
      // You can add more cases here as you add more tools
      // case "Affine Cipher":
      //   keyInput.placeholder = "Enter key 'a' and 'b' (e.g., 5,8)...";
      //   break;
      default:
        keyInput.placeholder = "Enter the key...";
    }
  }

  /**
   * Clears all input and output fields
   */
  function clearFields() {
    inputText.value = "";
    outputText.value = "";
    keyInput.value = "";
  }

  /**
   * Handles the main API call for encryption or decryption
   * @param {string} action - Either "encrypt" or "decrypt"
   */
  async function handleApiCall(action) {
    const text = inputText.value;
    const key = keyInput.value;
    let endpoint = "";
    let payload = {};
    
    // 'ct' means 'ciphertext', 'pt' means 'plaintext'
    // This logic determines what to send to the server
    const textKey = (action === "encrypt") ? "pt" : "ct";
    // This logic determines what to read from the server's response
    const resultKey = (action === "encrypt") ? "ct" : "pt"; 

    // Determine the correct endpoint and payload format
    switch (currentTool) {
      case "Ceaser Cipher":
        // Note: The backend route is "Ceaser" (with 'ea')
        endpoint = `${API_BASE_URL}/Ceaser/${action}`;
        payload = {
          [textKey]: text,
          key: parseInt(key) || 0 // Backend expects an integer
        };
        break;
        
      case "Multiplicative Cipher":
        endpoint = `${API_BASE_URL}/Multiplicative/${action}`;
        payload = {
          [textKey]: text,
          key: parseInt(key) || 1 // Backend expects an integer
        };
        break;

      // Add cases for your other ciphers here
      // e.g., case "Affine Cipher": ...

      default:
        outputText.value = "Error: No tool selected or tool is not implemented.";
        return;
    }

    // --- Perform the API request ---
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        // Handle errors from the backend (e.g., "Invalid key")
        outputText.value = `Error: ${data.error || "Unknown server error"}`;
      } else {
        // Success! Display the result
        outputText.value = data[resultKey];
      }
    } catch (error) {
      // Handle network errors (e.g., server is down)
      console.error("Fetch error:", error);
      outputText.value = "Error: Could not connect to the server. Is it running?";
    }
  }

  // --- Event Listeners ---

  // Add click listeners to all tool buttons
  toolButtons.forEach(button => {
    button.addEventListener("click", setActiveTool);
  });

  // Add click listeners to action buttons
  encryptBtn.addEventListener("click", () => handleApiCall("encrypt"));
  decryptBtn.addEventListener("click", () => handleApiCall("decrypt"));
  clearBtn.addEventListener("click", clearFields);

  // --- Initialization ---
  
  // Set the first tool as active by default
  if (toolButtons.length > 0) {
    toolButtons[0].classList.add("active");
    updateKeyPlaceholder(currentTool);
  }
});