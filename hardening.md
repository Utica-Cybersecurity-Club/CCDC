# Hardening

Below is a category-by-category guide to reducing attack surface for hosted services.
This is written in a practical, security-engineering style—easy to use as a hardening reference when building baselines.

## Web Servers (Apache, Nginx, IIS, Node, Tomcat, etc.)
A. Disable Unused Modules
- Apache: disable mod_status, mod_autoindex, mod_cgi, etc.
- Nginx: remove unused modules from builds or configs.
- IIS: disable WebDAV, .NET versions not needed.
B. Enforce TLS
- Redirect all HTTP → HTTPS
- Disable TLS 1.0 & 1.1
- Prefer TLS 1.3 + modern ciphers
C. Minimize What’s Exposed
- Do not expose admin consoles (Tomcat Manager, JMX, IIS Manager).
- Run apps behind reverse proxies to keep internals hidden.
D. Harden File & Directory Access
- Disable directory listing
- Limit static file locations
- Enforce least privilege on web roots
E. Sandboxing
- Run as non-root
- Use systemd sandboxing (ProtectHome=, MemoryDenyWriteExecute=, etc.)

## SQL Databases (MySQL, PostgreSQL, SQL Server, Oracle)
A. Network Hardening
- Bind only to localhost or internal networks
- Place DBs behind firewalls, not internet-accessible
- Enforce TLS for client connections
- Use proxy layers like PgBouncer or MySQL Proxy when possible
B. Authentication & Access Reduction
- Remove default accounts
- Disable guest/dbo-level permissions
- Enforce strong auth / rotate credentials
- Use PAM/AD integration where possible
C. Configuration Hardening
- Disable unused protocols (SQL Browser, legacy auth types)
- Disable stored procedures and scripting engines not needed
- Disable remote admin options unless isolated
D. Data & Process Isolation
- Run DB under a dedicated low-privilege account
- Isolate DB files with strict filesystem permissions
- Separate data, logs, temp dirs

## NoSQL Databases (MongoDB, Redis, Elasticsearch, Cassandra)
A. NETWORK RESTRICTION (Critical!)
Most are insecure by default if exposed.
- Bind to localhost or private LAN only
- Use firewalls or reverse proxies
- Never expose default ports to the internet
B. Authentication Everywhere
Many NoSQL engines allow anonymous access by default.
- Enable auth (Redis, MongoDB)
- Enable TLS
- Use PKI where supported
C. Disable Dangerous Features
- Disable scripting (Redis EVAL, Elasticsearch sandbox bypass risks)
- Disable HTTP APIs if not required
D. Data Node Isolation
- Separate cluster nodes from user-accessible networks
- Segment clusters with VLANs or SDN controls

## File Services (SMB, NFS, FTP, SFTP, WebDAV)
A. Disable Legacy Protocols
- SMBv1 (Disable everywhere)
- NTLMv1
- Anonymous/Guest shares
- NFSv3 if possible (use v4)
B. Limit Share Scope
- Avoid large "open to many" shares
- Use per-directory granular ACLs
- Prevent writable shares where not required
C. Authentication Hardening
- Require Kerberos for SMB
- For FTP → disable, or replace with SFTP
- Disable plaintext passwords
D. Limit Network Exposure
- Internal network only
- Firewalls on both sides
- Disable port 445 externally everywhere

## Directory & Identity Services (Active Directory, LDAP, RADIUS)
A. Protect Authentication Traffic
- Enforce LDAPS (LDAP over TLS)
- Require Kerberos wherever possible
- Disable LDAP anonymous binds
B. Limit Admin Interfaces
- Restrict RDP/SSH to domain controllers
- Use PAW machines (Privileged Access Workstations)
C. Constrain Identity Services
- Implement tiered admin model
- Disable legacy protocols:
    - NTLMv1
    - LM hash
- Remove outdated password hashing algorithms
D. Reduce Enumeration
- Limit user enumeration in LDAP
- Harden default ACLs
- Disable unused schema objects & roles

## Network Services (DNS, DHCP, Proxy, VPN, etc.)
**DNS Servers**
- Disable recursion or restrict to internal networks
- Disable zone transfers (allow-transfer { trusted-ips; };)
- Use DNSSEC
- Place DNS on isolated IPs
**DHCP**
- Limit scope ranges
- Use DHCP snooping on switches
- Enable failover to avoid rogue DHCP scenarios
- Proxy/Reverse Proxy (Squid, HAProxy, Nginx)
- Disable caching if not needed
- Limit access by IP/subnet
- Use strict ACLs
- Disable non-TLS upstream/downstream protocols where possible
**VPN Services**
- Use modern cipher suites (ChaCha20/Poly1305, AES-GCM)
- Disable L2TP/PPTP
- Prefer WireGuard or OpenVPN with TLS 1.3
- Require MFA for VPN access

## Email Services (SMTP, IMAP, POP, Exchange)
A. Lock Down Administrative Interfaces
- Block IMAP/POP externally
- Restrict admin URLs (ECP, OWA, Zimbra Admin)
- Use MFA for all admin accounts
B. Harden TLS & Mail Transfer
- Enforce STARTTLS everywhere
- Reject weak ciphers
- Enforce SPF, DKIM, DMARC
- Block open relays
C. Disable Legacy Auth
- Disable POP3/IMAP unless required
- Disable basic auth (O365/Exchange)

## Messaging / Queueing Services (Kafka, RabbitMQ, ActiveMQ, Redis Streams)
- Require TLS everywhere
- Remove default guest/anonymous accounts
- Use network ACLs to restrict producers/consumers
- Disable unsecured management consoles
- Use SASL auth for Kafka
- Place queues on isolated backend segments
- Disable cluster-exposed ports externally

## Monitoring & Logging Services (Prometheus, ELK, Splunk, Zabbix)
A. Protect Dashboards & APIs
- Require authentication for dashboards
- Don’t expose monitoring UIs to the internet
- Network-isolate the logging tier
B. Protect Agents
- Lock down Prometheus scrape endpoints
- Disable unauthenticated Elasticsearch APIs
- Use RBAC for Kibana/Elasticsearch
- Encrypt traffic (Filebeat → Logstash → Elasticsearch)
C. Storage Isolation
- Secure log storage directories
- Prevent log tampering via permissions
- Sign logs (Splunk has built-in integrity checking)

## Universal Principles (Easy to Apply Everywhere)
1. Reduce Listening Services
- Disable unused ports
- Stop services not needed
- Remove unnecessary packages
2. Restrict Network Exposure
- Segmentation
- Firewalls
- Private interfaces
- “Deny by default” inbound
3. Enforce Strong Authentication
- No anonymous access
- MFA where possible
- Integrate with AD/SAML OAuth
4. Enforce TLS Everywhere
- TLS 1.2+ minimum
- Valid certificates
- HSTS and secure cipher suites
5. Follow Least Privilege
- No root/Administrator services
- Dedicated service accounts
- Tight filesystem permissions
6. Enable Monitoring & Logging
- Centralized logging
- Alerting on unusual access
- Integrity checking
7. Remove Legacy Protocols
- SMBv1, NTLMv1
- TLS < 1.2
- Unencrypted LDAP
- FTP in plaintext
- PPTP or L2TP without IPsec



# GLOBAL PRINCIPLES (APPLY TO EVERY SERVICE)
### Service Accounts (Least Privilege)
**Never run a hosted service as**:
- Administrator (Windows)
- LocalSystem (Windows)
- root (Linux)
**Instead**:
- Create dedicated service accounts per daemon
    - Linux: `adduser --system --no-create-home --shell /usr/sbin/nologin <svcname>`
    - Windows: “Local Service” or custom domain account with no login rights
- Deny interactive login:
    - Linux: `/usr/sbin/nologin` or `/bin/false`
    - Windows: “Deny log on locally”, “Deny log on via RDP”
**Permissions**:
- Ownership of service files:
    - `/etc/<service>/` → root:root, 750
    - `/var/lib/<service>/data` → `<svcuser>:<svcgroup>`, 700
    - `/var/log/<service>/` → `<svcuser>:adm`, 750
- NEVER allow service accounts to write to:
    - `/etc` (except their own config dir)
    - `/usr`
    - application binaries
    - global logs
    - `/home` directories

### Filesystem Isolation
systemd service sandboxing (Linux):
Add to every service unit:
```ini
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
PrivateDevices=true
ReadWritePaths=/var/lib/<service> /var/log/<service>
```
This limits:
- Root filesystem → read-only
- No access to user home dirs
- Only service data/log dirs are writable

### Network
- Listen only on required interfaces (loopback whenever possible)
- Use host firewalls:
    - Linux: nftables / firewalld
    - Windows: Windows Defender Firewall
- Default-deny inbound
- Disable IPv6 if not used
- For internal listening, bind to:
    - Linux: `127.0.0.1` or `::1`
    - Windows: Local Address filtering in firewall

### TLS Everywhere
- Enforce minimum: TLS 1.2 (prefer TLS 1.3)
- Disable:
    - RC4
    - 3DES
    - EXPORT ciphers
    - Anonymous DH
- Use modern cipher suites like:
    - `TLS_AES_256_GCM_SHA384`
    - `TLS_CHACHA20_POLY1305_SHA256`
- Use OS trust store, not custom CAs unless required.

### Logging & Audit
- Write application logs only to their own directory (700 perms)
- Forward logs to SIEM via syslog/Winlogbeat/FluentBit
- Enable:
    - Windows: Object Access Auditing
    - Linux: auditd rules for service config directories


## WEB SERVERS
(Covers: Apache, Nginx, IIS, Node.js, Tomcat, Jetty, etc.)

A. Permissions & Directory Layout
Linux:
```bash
/etc/nginx             root:root 755 (configs 640)
/var/www/<site>        www-data:www-data 750
/var/log/nginx         www-data:adm 750
```
Windows:
    - IIS Site directories:
    - Owner: Administrators
    - Read/Execute: IIS_IUSRS
    - No write permissions for web users
- Disable “Write” permission unless intentional

B. Disable Features
- Remove directory listing
- Disable server tokens / headers (hide versions)
- Disable unneeded modules:
    - Apache: proxy, cgi, status, autoindex
    - Nginx: unused modules compiled out
    - IIS: remove legacy ASP, WebDAV, FTP unless used

C. Network
- Bind to localhost if behind reverse proxy
- Use firewall rules restricting access to:
    - Internal admins
    - Load balancers
    - Reverse proxies

D. Sandboxing
Linux systemd unit:
```ini
User=www-data
Group=www-data
CapabilityBoundingSet=
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ReadWritePaths=/var/www /var/log/nginx
```

## SQL DATABASES
(MariaDB, MySQL, PostgreSQL, Oracle, SQL Server)

A. Permissions
Linux:
```bash
/var/lib/mysql       mysql:mysql 700
/var/lib/postgresql  postgres:postgres 700
/etc/mysql           root:root 750 (config files 640)
/etc/postgresql      root:postgres 750
```
Windows SQL Server:
- Service account:
    - “NT SERVICE\MSSQLSERVER” (least privilege as default)
- Disallow interactive logon
- Database files:
    - Allow: SQL service account
    - Deny: Everyone else
    - No Administrator write access (only full control but avoid direct writes)

B. Disable/Restrict
- Disable remote root login
- Disable local file load functions:
    - MySQL: `local_infile=0`
    - PostgreSQL: restrict `COPY TO/FROM PROGRAM`
- Disable unused DB engines or plugins
- Disable MySQL's performance schema if not needed

C. Network
- Bind to internal only:
    - MySQL: `bind-address=127.0.0.1`
    - Postgres: `listen_addresses='localhost'`
- Disable:
    - MySQL: `skip-symbolic-links`
    - Postgres: `trust` authentication in `pg_hba.conf`

D. TLS
- Require SSL for all connections:
    - MySQL: `require_secure_transport=ON`
    - PostgreSQL: `hostssl` rules only

## NOSQL DATABASES
(MongoDB, Redis, Elasticsearch, Cassandra)
These systems are notoriously insecure by default.

### Redis
```bash
Permissions:
/var/lib/redis   redis:redis 700
/etc/redis       root:redis 750
```
Disable:
- `protected-mode no` → must be yes
- `bind 127.0.0.1`
- Disable `SAVE` commands when not needed
- Rename dangerous commands:
```lua
rename-command FLUSHALL ""
rename-command CONFIG   ""
```

### MongoDB
Disable:
- Bind to localhost only unless clustered
- Disable HTTP interface
- Disable server-side JavaScript unless needed
Permissions:
```bash
dbPath: /var/lib/mongodb    mongodb:mongodb 700
logpath: /var/log/mongodb   mongodb:adm 750
```

### Elasticsearch
Disable:
- `discovery.type=single-node` for production
- Disable open APIs
- Require Basic/Auth proxy via reverse proxy
- Disable scripting:
```ini
script.allowed_types=none
```

## FILE SERVICES
(SMB/Samba, NFS, FTP/SFTP, WebDAV)

### SMB / Samba
Disable:
- SMBv1
- Guest access
- NTLMv1
- LANMAN hashes
Permissions:
- Use POSIX ACLs:
```bash
setfacl -m u:username:rwx /srv/share
```
- Avoid 777 permissions ever
Samba config must include:
```java
server min protocol = SMB2_02
encrypt passwords = yes
restrict anonymous = 2
```

### NFS
Disable:
- NFSv2
- NFSv3 UDP
- world-writable exports
Export example:
```bash
/srv/data 10.0.0.0/24(rw,sync,no_root_squash,sec=krb5p)
```
- Use `sec=krb5p` (encrypted)
- Avoid `no_root_squash` unless required

### FTP / SFTP
- Disable FTP entirely
- Prefer SFTP (OpenSSH subsystem)
- Permissions:
```bash
/sftp/userdir  root:root 755
/sftp/userdir/data user:user 700
```

## DIRECTORY & IDENTITY SERVICES (AD, LDAP)

**Active Directory**
Disable:
- Anonymous binds
- LM/NTLMv1
- SMBv1
- WDigest
Permissions:
- Domain controllers ACL lockdown:
    - No users with local admin on DC
    - Only Domain Admins → Administrators group
    - Never install software on DCs
Network:
- Restrict access to LDAP, Kerberos, RPC only from domain hosts
- Block LDAP from internet

**LDAP (OpenLDAP)**
Permissions:
- `/etc/openldap` → root:root 750
- Database directories → ldap:ldap 700
Disable:
- anonymous bind
- insecure binds
- plain LDAP

## NETWORK SERVICES (DNS, DHCP, PROXY, VPN)

**DNS (BIND, PowerDNS, Windows DNS)**
Permissions:
```bash
/var/named  named:named 750
/etc/named  root:named 750
```
Disable:
- Recursion on public servers
- Zone transfers
- DNS over TCP unless required
Configuration:
```sql
allow-recursion { internal-subnet; };
allow-transfer { none; };
```

**DHCP**
Restrict:
- Authorized servers only (Windows)
- DHCP snooping on network switches

**Proxy (Squid, HAProxy)**
Permissions:
```bash
/var/spool/squid   squid:squid 700
/var/log/squid     squid:adm 750
```
Disable:
- CONNECT to non-SSL ports
- All methods except GET/POST unless required
Network:
- Allow access only from internal network ranges

**VPN**
Disable:
- PPTP
- L2TP without IPsec
- Weak ciphers
Strong configs:
- OpenVPN TLS 1.3
- WireGuard with private key permissions:
```bash
chmod 600 /etc/wireguard/private.key
```

## MESSAGE QUEUES
(RabbitMQ, Kafka, ActiveMQ)

**RabbitMQ**
Disable/Restrict:
- guest/guest account
- Management UI publicly exposed
Permissions:
```bash
/var/lib/rabbitmq    rabbitmq:rabbitmq 700
/etc/rabbitmq        root:rabbitmq 750
```

**Kafka**
- Disable unauthenticated PLAINTEXT listeners
- Require SASL/SCRAM or Kerberos
- Restrict topic permissions per service user

## MONITORING & LOGGING
(Prometheus, Grafana, ELK, Splunk)

**Elasticsearch**
- Disable scripting
- RBAC only via X-Pack security
- Protect data dirs:
```bash
/var/lib/elasticsearch elasticsearch:elasticsearch 700
```
**Kibana**
- Require SSO
- Bind to localhost when behind a proxy

**Prometheus**
- Don’t expose /metrics to the world
- Protect with reverse proxy + auth