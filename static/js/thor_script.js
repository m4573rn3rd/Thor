console.log("Thor UI Script Loaded.");

document.addEventListener('DOMContentLoaded', () => {
    // Only connect if we are on a page that needs real-time updates.
    const trapsTable = document.querySelector('#traps-table-body');
    const logsTable = document.querySelector('#logs-table-body');

    if (trapsTable || logsTable) {
        console.log("Connecting to SSE event stream...");
        const eventSource = new EventSource("/stream");

        eventSource.addEventListener('new_trap', function(event) {
            const trap = JSON.parse(event.data);
            if (trapsTable) {
                const newRow = document.createElement('tr');
                let varbindsHtml = '<pre>';
                trap.varbinds.forEach(vb => {
                    varbindsHtml += `OID: ${vb.oid}\nValue: ${vb.value}\n\n`;
                });
                varbindsHtml += '</pre>';

                newRow.innerHTML = `
                    <td>${trap.id}</td>
                    <td>${trap.received_at}</td>
                    <td>${trap.source_ip}</td>
                    <td>${varbindsHtml}</td>
                `;
                trapsTable.prepend(newRow);
            }
        });

        eventSource.addEventListener('new_log', function(event) {
            const log = JSON.parse(event.data);
            if (logsTable) {
                const newRow = document.createElement('tr');
                newRow.innerHTML = `
                    <td>${log.timestamp}</td>
                    <td class="log-level-${log.level}">${log.level}</td>
                    <td>${log.thread_name}</td>
                    <td>${log.message}</td>
                `;
                logsTable.prepend(newRow);
            }
        });

        eventSource.onerror = function(err) {
            console.error("EventSource failed:", err);
        };
    }

    // --- Live Clock for Dashboard ---
    const timeElement = document.getElementById("time");
    if (timeElement) {
        window.setInterval(() => {
            const time = new Date();
            // This is a 'beacon' to send data without expecting a response
            new Image().src = "/getTime?time=" + time;
            timeElement.innerHTML = time.toLocaleTimeString();
        }, 1000);
    }
});