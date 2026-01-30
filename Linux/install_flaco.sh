#!/bin/bash

loki_url=$1
if [[ "$loki_url" == "" ]]; then
    echo Please pass in Loki URL
    exit 1
fi

falco_apt_install() {
    sudo apt-get update -y
    sudo apt install -y curl gawk sed

    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
        sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
        sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
    sudo apt-get update -y
    sudo apt-get install -y falco
}

falco_yum_install() {
    sudo yum update -y
    sudo yum install -y curl gawk sed

    sudo rpm --import https://falco.org/repo/falcosecurity-packages.asc
    sudo curl -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
    sudo yum update -y
    sudo yum install -y --nogpgcheck falco
}

falco_zypper_install() {
    sudo zypper -n update
    sudo zypper -n install curl gawk sed

    sudo rpm --import https://falco.org/repo/falcosecurity-packages.asc
    sudo curl -o /etc/zypp/repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
    sudo zypper -n update
    sudo zypper -n install falco
}

sidekick_install() {
    sudo mkdir -p /etc/falcosidekick
    wget https://github.com/falcosecurity/falcosidekick/releases/download/2.27.0/falcosidekick_2.27.0_linux_amd64.tar.gz \
        && sudo tar -C /usr/local/bin/ -xzf falcosidekick_2.27.0_linux_amd64.tar.gz
    echo """loki:
  hostport: ${loki_url}
  format: "text"
  endpoint: "/loki/api/v1/push"""" | sudo tee /etc/falcosidekick/config.yaml
  echo """[Unit]
Description=Falcosidekick
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart=/usr/local/bin/falcosidekick -c /etc/falcosidekick/config.yaml
EOF""" | sudo tee /etc/systemd/system/falcosidekick.service > /dev/null
    sudo systemctl enable falcosidekick
    sudo systemctl start falcosidekick

    sudo cp /etc/falco/falco.yaml /etc/falco/falco.yaml.bak
    sudo sed -i 's/^json_output: false$/json_output: true/' /etc/falco/falco.yaml

    awk '
        # Detect start of http_output section
        /^http_output:/ {
            in_section = 1
            print
            next
        }

        # Detect start of another top-level section
        /^[^[:space:]].*:/ && in_section {
            in_section = 0
        }

        # Modify enabled within http_output
        in_section && /^[[:space:]]*enabled:[[:space:]]*/ {
            sub(/enabled:.*/, "enabled: true")
        }

        # Modify url within http_output
        in_section && /^[[:space:]]*url:[[:space:]]*/ {
            sub(/url:.*/, "url: \"http://localhost:2801\"")
        }

        { print }
    ' /etc/falco/falco.yaml | sudo tee /etc/falco/falco.yaml > /dev/null

    sudo systemctl restart falco.service
}

if command -v apt-get >/dev/null; then
    falco_apt_install
elif command -v yum >/dev/null; then
    falco_yum_install
elif command -v zypper >/dev/null; then
    falco_zypper_install
else
    echo "No package manager found"
    exit 1
fi

sidekick_install

