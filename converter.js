var data_bug = ["cf-vod.nimo.tv", "104.18.53.42"];

function updateBug() {
    var bugList = document.getElementById("bugList");
    var selectedBug = bugList.options[bugList.selectedIndex].value;
    return selectedBug; // Mengembalikan nilai bug yang baru dipilih
}

function convertToYAML() {
    var vmessInput = document.getElementById("vmessInput").value.trim();
    var vmessArray = vmessInput.split('\n');
    var yamlOutput = "proxies:\n";

    // Perbarui bug setelah pemilihan dari daftar
    var bug = updateBug();

    vmessArray.forEach(function (line) {
        if (line.trim() !== "") {
            var vmessData = parseVmess(line.trim());
            if (vmessData !== null) {
                var randomString = Math.random().toString(36).substring(2, 6); // 4 characters alphanumeric
                // Determine the name based on conditions
                var name = (vmessData.add !== "" && !data_bug.includes(vmessData.add)) ? vmessData.add : vmessData.host;

                yamlOutput += "  - name: " + name + "-" + randomString + "\n";
                yamlOutput += "    type: vmess\n";
                yamlOutput += "    server: " + bug + "\n";
                yamlOutput += "    port: " + vmessData.port + "\n";
                yamlOutput += "    uuid: " + vmessData.id + "\n";
                yamlOutput += "    alterId: " + vmessData.aid + "\n";
                yamlOutput += "    cipher: auto\n";
                yamlOutput += "    tls: true\n";
                yamlOutput += "    skip-cert-verify: true\n";
                yamlOutput += "    servername: " + name + "\n";
                yamlOutput += "    network: " + vmessData.net + "\n";

                if (vmessData.net === "grpc") {
                    yamlOutput += "    grpc-opts:\n";
                    yamlOutput += "      grpc-service-name: " + vmessData.path + "\n";
                } else if (vmessData.net === "ws") {
                    yamlOutput += "    ws-opts:\n";
                    yamlOutput += "      path: " + vmessData.path + "\n";
                    yamlOutput += "      headers: Host: " + vmessData.host + "\n";
                }

                yamlOutput += "    udp: true\n";
            }
        }
    });

    document.getElementById("yamlOutput").value = yamlOutput;
}

function parseVmess(vmess) {
    try {
        var decoded = atob(vmess.split("://")[1]);
        return JSON.parse(decoded);
    } catch (error) {
        console.error("Failed to parse Vmess:", error);
        return null;
    }
}
