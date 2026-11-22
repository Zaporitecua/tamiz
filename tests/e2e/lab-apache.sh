#!/bin/sh
# Lab for tests/e2e/test_apache_lab.py: Apache httpd + mod_security2 + CRS on
# :8081. Run after lab-nginx.sh (it creates the tamiz user and sshd).
set -eu

apt-get install -y -qq apache2 libapache2-mod-security2 modsecurity-crs

cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/^SecRuleEngine .*/SecRuleEngine On/;
        s#^SecAuditLog .*#SecAuditLog /var/log/apache2/modsec_audit.log#' /etc/modsecurity/modsecurity.conf
# Tamiz's directories around the CRS. IncludeOptional tolerates empty globs.
cat > /etc/apache2/mods-available/security2.conf <<'EOF'
<IfModule security2_module>
	SecDataDir /var/cache/modsecurity
	IncludeOptional /etc/modsecurity/*.conf
	IncludeOptional /etc/modsecurity/tamiz/before/*.conf
	IncludeOptional /usr/share/modsecurity-crs/*.load
	IncludeOptional /etc/modsecurity/tamiz/after/*.conf
</IfModule>
EOF
mkdir -p /etc/modsecurity/tamiz && chown tamiz:tamiz /etc/modsecurity/tamiz
sed -i 's/^Listen 80$/Listen 8081/; /^Listen 443/d' /etc/apache2/ports.conf
sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8081>/' /etc/apache2/sites-available/000-default.conf
echo "ServerName lab.local" > /etc/apache2/conf-enabled/servername.conf

cat >> /etc/sudoers.d/tamiz <<'EOF'
tamiz ALL=(root) NOPASSWD: /usr/sbin/apachectl -t, /usr/sbin/apachectl -t -D DUMP_INCLUDES, /usr/sbin/apachectl graceful, /usr/bin/tail ^-c [0-9]+ -- /var/log/apache2/modsec_audit\.log$, /usr/bin/tail ^-c [0-9]+ -- /var/log/apache2/error\.log$
EOF
visudo -cf /etc/sudoers.d/tamiz
apachectl -t && (apachectl graceful 2>/dev/null || apachectl start)
echo "apache lab ready on :8081"
