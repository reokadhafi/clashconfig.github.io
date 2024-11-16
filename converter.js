var data_bug = ["cf-vod.nimo.tv", "104.18.53.42", "172.64.146.115", "app-stg.gopay.co.id"];

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
                    if (bug === "app-stg.gopay.co.id") {
                        yamlOutput += "    port: 443\n";
                    } else {
                        yamlOutput += "    port: 80\n";
                    }
                }
                yamlOutput += "    uuid: " + vmessData.id + "\n";
                yamlOutput += "    alterId: " + vmessData.aid + "\n";
                yamlOutput += "    cipher: auto\n";
                if (vmessData.net === "grpc") {
                    yamlOutput += "    tls: true\n";
                } else if (vmessData.net === "ws") {
                    if (bug === "app-stg.gopay.co.id") {
                        yamlOutput += "    tls: true\n";
                    } else {
                        yamlOutput += "    tls: false\n";
                    }
                }
                yamlOutput += "    skip-cert-verify: true\n";
                yamlOutput += "    servername: " + name + "\n";
                yamlOutput += "    network: " + vmessData.net + "\n";
                if (vmessData.net === "grpc") {
                    yamlOutput += "    grpc-opts:\n";
                    yamlOutput += "      grpc-service-name: " + vmessData.path + "\n";
                } else if (vmessData.net === "ws") {
                    yamlOutput += "    ws-opts:\n";
                    yamlOutput += "      path: " + vmessData.path + "\n";
                    yamlOutput += "      headers:" + "\n";
                    yamlOutput += "        Host: " + name + "\n";
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
                yamlOutput += "    server: " + bug + "\n";
                if (trojanData.jenis === "vless" && trojanData.type === "ws") {
                    yamlOutput += "    port: 80\n";
                } else if (trojanData.jenis === "vless" && trojanData.type === "grpc") {
                    yamlOutput += "    port: 443\n";
                } else if (trojanData.jenis === "trojan") {
                    yamlOutput += "    port: 443\n";
                }
                if (trojanData.jenis === "vless" && trojanData.type === "ws") {
                    yamlOutput += "    uuid: " + trojanData.password + "\n";
                    yamlOutput += "    tls: false\n";
                } else if (trojanData.jenis === "vless" && trojanData.type === "grpc") {
                    yamlOutput += "    uuid: " + trojanData.password + "\n";
                    yamlOutput += "    tls: true\n";
                } else if (trojanData.jenis === "trojan") {
                    yamlOutput += "    password: " + trojanData.password + "\n";
                    yamlOutput += "    tls: true\n";
                }
                yamlOutput += "    skip-cert-verify: true\n";
                yamlOutput += "    sni: " + name + "\n";
                yamlOutput += "    network: " + trojanData.type + "\n";
                if (trojanData.type === "grpc") {
                    yamlOutput += "    grpc-opts:\n";
                    yamlOutput += "      grpc-service-name: " + trojanData.service_name + "\n";
                } else if (trojanData.type === "ws") {
                    yamlOutput += "    ws-opts:\n";
                    yamlOutput += "      path: " + trojanData.path + "\n";
                    yamlOutput += "      headers:" + "\n";
                    yamlOutput += "        Host: " + name + "\n";
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
    try {
        // Ganti skema trojan:// menjadi http:// agar URL parsing berjalan
        if (url.startsWith("trojan://")) {
            url = url.replace("trojan://", "http://");
        }

        // Gunakan URL object untuk parsing
        const parsed_url = new URL(url);

        let jenis = "trojan"; // Default jenis adalah trojan
        let password = ""; // Default password kosong
        let server = ""; // Default server kosong
        let port = parsed_url.port || "443"; // Default port adalah 443
        const query_params = new URLSearchParams(parsed_url.search); // Ambil query params

        // Ekstraksi SNI, type, host, path, dan service name dari query
        let sni = query_params.get("sni") || "";
        let type = query_params.get("type") || ""; // ws atau grpc
        let host = query_params.get("host") || "";
        let path = query_params.get("path") || "/";
        let service_name = query_params.get("serviceName") || "";

        // Cek kredensial di bagian authority (username:password@hostname)
        if (parsed_url.username) {
            password = parsed_url.username; // Password diambil dari username (karena skema HTTP diubah)
            server = parsed_url.hostname; // Hostname langsung diambil
        } else {
            // Cek kredensial di path jika tidak ada username
            const path_parts = parsed_url.pathname.split("@");
            if (path_parts.length === 2) {
                password = path_parts[0].replace(/^\/\//, ""); // Ambil password sebelum @
                server = path_parts[1].split(":")[0]; // Ambil server setelah @
            }
        }

        // Buat objek data hasil parsing
        const data_dict = {
            "jenis": jenis,
            "password": password,
            "server": server,
            "port": port,
            "sni": sni,
            "type": type,
            "host": host,
            "path": path,
            "service_name": service_name,
        };

        // Tambahkan properti tambahan berdasarkan type
        if (type === "") {
            // Jika type kosong, set semua nilai ke null
            for (const key in data_dict) {
                data_dict[key] = null;
            }
        } else if (type === "grpc") {
            // Jika type adalah grpc, tambahkan properti untuk gRPC
            data_dict["network"] = "grpc";
            data_dict["grpc-service-name"] = service_name;
        }

        return data_dict;
    } catch (error) {
        console.error("Failed to parse Trojan URL:", error);
        return null; // Kembalikan null jika terjadi error
    }
}
