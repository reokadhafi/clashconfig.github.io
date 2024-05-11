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
    var log = "\n"
    var bug = updateBug();

    vmessArray.forEach(function (line) {
        if (line.trim() !== "") {
            var vmessData = parseVmess(line.trim());
            var trojanData = parseTrojan(line.trim());
            if (vmessData !== null) {
                var randomString = Math.random().toString(36).substring(2, 6);
                var name = "";
                if (vmessData.add !== "" && !data_bug.includes(vmessData.add)) {
                    name = vmessData.add;
                } else if (vmessData.host !== "" && !data_bug.includes(vmessData.host)) {
                    name = vmessData.host;
                } else if (vmessData.sni !== "" && !data_bug.includes(vmessData.sni)) {
                    name = vmessData.sni;
                }
                yamlOutput += "  - name: " + name + "-" + randomString + "\n";
                yamlOutput += "    type: vmess\n";
                yamlOutput += "    server: " + bug + "\n";
                if (vmessData.net === "grpc") {
                    yamlOutput += "    port: 443\n";
                } else if (vmessData.net === "ws") {
                    yamlOutput += "    port: 80\n";
                }
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
                    yamlOutput += "      headers: Host: " + name + "\n";
                }
                yamlOutput += "    udp: true\n";
            } else if (trojanData !== null) {
                var randomString = Math.random().toString(36).substring(2, 6);
                var name = "";
                if (trojanData.server !== "" && !data_bug.includes(trojanData.server)) {
                    name = trojanData.server;
                } else if (trojanData.host !== "" && !data_bug.includes(trojanData.host)) {
                    name = trojanData.host;
                } else if (trojanData.sni !== "" && !data_bug.includes(trojanData.sni)) {
                    name = trojanData.sni;
                }
                yamlOutput += "  - name: " + name + "-" + randomString + "\n";
                yamlOutput += "    type: " + trojanData.jenis + "\n";
                if (trojanData.jenis === "vless" && trojanData.type === "ws") {
                    yamlOutput += "    port: 80\n";
                } else if (trojanData.jenis === "vless" && trojanData.type === "grpc") {
                    yamlOutput += "    port: 443\n";
                } else if (trojanData.jenis === "trojan") {
                    yamlOutput += "    port: 443\n";
                }
                yamlOutput += "    server: " + bug + "\n";
                yamlOutput += "    password: " + trojanData.password + "\n";
                yamlOutput += "    tls: true\n";
                yamlOutput += "    skip-cert-verify: true\n";
                yamlOutput += "    sni: " + name + "\n";
                yamlOutput += "    network: " + trojanData.type + "\n";
                if (trojanData.type === "grpc") {
                    yamlOutput += "    grpc-opts:\n";
                    yamlOutput += "      grpc-service-name: " + trojanData.service_name + "\n";
                } else if (trojanData.type === "ws") {
                    yamlOutput += "    ws-opts:\n";
                    yamlOutput += "      path: " + trojanData.path + "\n";
                    yamlOutput += "      headers: Host: " + name + "\n";
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

function parseTrojan(url) {
    var parsed_url = new URL(url);
    var jenis = url.split("://")[0]
    var password = "";
    var server = "";
    var port = parsed_url.port || 443; // Default port for trojan
    var query_params = new URLSearchParams(parsed_url.search);
    var sni = query_params.get("sni") || "";
    var type = query_params.get("type") || "";
    var host = query_params.get("host") || "";
    var path = query_params.get("path") || "";
    var service_name = query_params.get("serviceName") || "";

    // Check if credentials are in the authority
    if (parsed_url.username && parsed_url.password) {
        password = parsed_url.password;
        server = parsed_url.username + "@" + parsed_url.hostname;
    } else {
        // If not, try to extract credentials from the path
        var path_parts = parsed_url.pathname.split("@");
        if (path_parts.length === 2) {
            password = path_parts[0].replace(/^\/\//, '');
            server = path_parts[1].split(":")[0];
        }
    }

    var data_dict = {
        "jenis": jenis,
        "password": password,
        "server": server,
        "port": port,
        "sni": sni,
        "type": type,
        "host": host,
        "path": path,
        "service_name": service_name
    };

    if (type === "") {
        for (var key in data_dict) {
            data_dict[key] = null;
        }
    } else if (type === "grpc") {
        data_dict["network"] = "grpc";
        data_dict["grpc-service-name"] = service_name;
    }

    return data_dict;
}
