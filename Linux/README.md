`audit_users_groups.sh`
Audit users, groups, permissions, and sudoers. Remove users from sudo.
Usage:
```bash
sudo ./script.sh list              # show users, groups, sudoers
sudo ./script.sh remove <user>     # remove user from sudoers
```

`backup.sh`
message
Usage:
```bash
sudo backup.sh 
```

`crontabcat.sh`
Read all user crontabs and print them to the console
Usage: `./crontabcat.sh`

`install_falco.sh`
Installs Falco and Falco sidekick using apt, zypper or yum. Takes in the URL of the Loki instance as a command-line argument.
Usage: `./install_falco.sh [Loki URL]`

`wazuh.sh`
Installs Wazuh through Docker

`forensics.sh`
List of helpful commands

`script.sh`
First iteration of a Hardening Script with a few flaws which needs polishing
Usage: `./script.sh`

`hardening.sh`
Second iteration of a Hardening Script
Usage:
```bash
sudo ./hardening.sh

-h, --helpDisplay   help message-v
--verbose           Enable verbose output
--restore           Restore from most recent backup
--skip-update       Skip system package updates
--minimal           Skip optional heavy components (Suricata, ClamAV, AIDE)
```


`hardeningV2.sh`
Third iteration of a Hardening Script with different OS support
Usage:
```bash
# Detect and harden any Linux distribution
sudo ./hardeningV2.sh

-h, --help   help message-v
-v, --verbose           Enable verbose output
--restore           Restore from most recent backup
--skip-update       Skip system package updates
--minimal           Skip optional heavy components (Suricata, ClamAV, AIDE)
```

`list-open-services.sh`

`block_and_log.sh`

wazuh-install 
--> https://github.com/CCDC-RIT/Logging-Scripts/blob/main/wazuh-install.sh
wazuh-manager
--> https://github.com/CCDC-RIT/Logging-Scripts/blob/main/wazuh-manager.sh
wazuh window rules
--> https://github.com/CCDC-RIT/Logging-Scripts/blob/main/windows_rules.xml