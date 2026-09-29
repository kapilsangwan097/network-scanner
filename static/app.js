document.addEventListener("DOMContentLoaded", () => {
    const subnetInput = document.getElementById("subnet-input");
    const scanBtn = document.getElementById("scan-btn");
    const exportBtn = document.getElementById("export-btn");
    const scanSpinner = document.getElementById("scan-spinner");
    const btnText = scanBtn.querySelector(".btn-text");
    const tableBody = document.getElementById("table-body");
    const deviceCount = document.getElementById("device-count");
    const errorBanner = document.getElementById("error-banner");

    let currentDevices = [];
    
    // Load custom names from browser local storage
    const customNames = JSON.parse(localStorage.getItem('networkScannerNames')) || {};

    // Fetch default subnet on load
    fetch("/api/subnet")
        .then(res => res.json())
        .then(data => {
            if (data.subnet) {
                subnetInput.value = data.subnet;
            }
        })
        .catch(err => console.error("Failed to load default subnet", err));

    // Scan button click
    scanBtn.addEventListener("click", async () => {
        const subnet = subnetInput.value.trim();
        if (!subnet) return;

        // UI State: Loading
        scanBtn.disabled = true;
        exportBtn.disabled = true;
        btnText.textContent = "Scanning...";
        scanSpinner.classList.remove("hidden");
        errorBanner.classList.add("hidden");
        
        tableBody.innerHTML = `
            <tr class="empty-state">
                <td colspan="4">Scanning network... This may take up to 10 seconds.</td>
            </tr>
        `;
        deviceCount.textContent = "0";

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ subnet })
            });

            const data = await response.json();

            if (data.status === "success") {
                currentDevices = data.devices;
                renderTable(currentDevices);
                if (currentDevices.length > 0) {
                    exportBtn.disabled = false;
                }
            } else {
                showError(data.message || "An unknown error occurred.");
                renderEmpty("Scan failed.");
            }
        } catch (error) {
            showError("Network error: Could not reach the server.");
            renderEmpty("Scan failed.");
        } finally {
            // UI State: Reset
            scanBtn.disabled = false;
            btnText.textContent = "Start Scan";
            scanSpinner.classList.add("hidden");
        }
    });

    // Export button click
    exportBtn.addEventListener("click", () => {
        if (currentDevices.length === 0) return;

        // Create CSV content
        const headers = ["IP Address", "MAC Address", "Device Name", "Manufacturer/Vendor"];
        const csvRows = [headers.join(",")];
        
        for (const device of currentDevices) {
            const resolvedName = device.hostname !== "Unknown" ? device.hostname : "";
            const displayName = customNames[device.mac] || resolvedName || "Unknown";
            
            const row = [device.ip, device.mac, `"${displayName}"`, `"${device.vendor}"`];
            csvRows.push(row.join(","));
        }
        
        const csvString = csvRows.join("\n");
        const blob = new Blob([csvString], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        
        // Trigger download
        const a = document.createElement("a");
        a.setAttribute("hidden", "");
        a.setAttribute("href", url);
        a.setAttribute("download", "network_scan_results.csv");
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    });

    function renderTable(devices) {
        if (devices.length === 0) {
            renderEmpty("No devices found on this subnet.");
            return;
        }

        deviceCount.textContent = devices.length;
        tableBody.innerHTML = "";

        devices.forEach(device => {
            const tr = document.createElement("tr");
            
            // Determine what name to show
            const resolvedName = device.hostname !== "Unknown" ? device.hostname : "";
            const displayName = customNames[device.mac] || resolvedName || "Unknown";
            const isCustom = !!customNames[device.mac];
            
            tr.innerHTML = `
                <td class="ip-cell">${device.ip}</td>
                <td class="mac-cell">${device.mac}</td>
                <td class="hostname-cell">
                    <div class="name-editor" data-mac="${device.mac}">
                        <span class="name-display ${isCustom ? 'custom-name' : (displayName === 'Unknown' ? 'unknown-name' : '')}">${displayName}</span>
                        <input type="text" class="name-input hidden" value="${displayName !== 'Unknown' ? displayName : ''}" placeholder="Enter device name...">
                        <button class="edit-btn" title="Edit Name">✏️</button>
                    </div>
                </td>
                <td class="vendor-cell">${device.vendor}</td>
            `;
            
            tableBody.appendChild(tr);
        });
        
        // Attach edit listeners
        attachEditListeners();
    }
    
    function attachEditListeners() {
        document.querySelectorAll('.name-editor').forEach(editor => {
            const mac = editor.getAttribute('data-mac');
            const displaySpan = editor.querySelector('.name-display');
            const inputField = editor.querySelector('.name-input');
            const editBtn = editor.querySelector('.edit-btn');
            
            // Click edit button to toggle input
            editBtn.addEventListener('click', () => {
                displaySpan.classList.add('hidden');
                editBtn.classList.add('hidden');
                inputField.classList.remove('hidden');
                inputField.focus();
            });
            
            // Save on enter or blur
            const saveName = () => {
                const newName = inputField.value.trim();
                if (newName) {
                    customNames[mac] = newName;
                    displaySpan.textContent = newName;
                    displaySpan.className = 'name-display custom-name';
                } else {
                    delete customNames[mac];
                    // Find original name from currentDevices
                    const device = currentDevices.find(d => d.mac === mac);
                    const origName = device && device.hostname !== "Unknown" ? device.hostname : "Unknown";
                    displaySpan.textContent = origName;
                    displaySpan.className = 'name-display ' + (origName === 'Unknown' ? 'unknown-name' : '');
                }
                
                // Save to local storage
                localStorage.setItem('networkScannerNames', JSON.stringify(customNames));
                
                // Reset UI
                displaySpan.classList.remove('hidden');
                editBtn.classList.remove('hidden');
                inputField.classList.add('hidden');
            };
            
            inputField.addEventListener('blur', saveName);
            inputField.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') saveName();
            });
        });
    }

    function renderEmpty(message) {
        tableBody.innerHTML = `
            <tr class="empty-state">
                <td colspan="4">${message}</td>
            </tr>
        `;
        deviceCount.textContent = "0";
    }

    function showError(message) {
        errorBanner.textContent = message;
        errorBanner.classList.remove("hidden");
    }
});
