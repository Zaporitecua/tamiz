#!/bin/sh
# Lab for tests/e2e: nginx + libmodsecurity v3 + OWASP CRS on :8080, sshd on
# :2222 and a "tamiz" user with a narrow sudoers rule. Ubuntu 24.04, as root.
# Run once, then: TAMIZ_E2E=1 python3 -m pytest tests/e2e
set -eu

apt-get install -y -qq nginx libnginx-mod-http-modsecurity modsecurity-crs openssh-server sudo curl

mkdir -p /etc/nginx/modsec/tamiz /var/www/lab
cp /etc/modsecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
sed -i 's/^SecRuleEngine .*/SecRuleEngine On/;
        s#^SecAuditLog .*#SecAuditLog /var/log/modsec_audit.log#;
        s/^SecAuditLogParts .*/SecAuditLogParts ABIJDEFHZ/;
        s/^SecRequestBodyInMemoryLimit/#SecRequestBodyInMemoryLimit/' /etc/nginx/modsec/modsecurity.conf
cp /etc/modsecurity/unicode.mapping /etc/nginx/modsec/
# The test rewrites main.conf; this is the starting point (no Tamiz includes).
cat > /etc/nginx/modsec/main.conf <<'EOF'
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/modsecurity/crs/crs-setup.conf
Include /usr/share/modsecurity-crs/rules/*.conf
EOF
echo '<h1>lab</h1>' > /var/www/lab/index.html
cat > /etc/nginx/sites-enabled/lab <<'EOF'
server {
    listen 8080;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
    root /var/www/lab;
    location / { try_files $uri /index.html; }
}
EOF
rm -f /etc/nginx/sites-enabled/default

id tamiz >/dev/null 2>&1 || useradd -m -s /bin/bash tamiz
mkdir -p /home/tamiz/.ssh /root/tamiz-keys
[ -f /root/tamiz-keys/lab_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/tamiz-keys/lab_ed25519 -C tamiz-lab
cp /root/tamiz-keys/lab_ed25519.pub /home/tamiz/.ssh/authorized_keys
chown -R tamiz:tamiz /home/tamiz/.ssh /etc/nginx/modsec/tamiz
chmod 700 /home/tamiz/.ssh && chmod 600 /home/tamiz/.ssh/authorized_keys

# sudo_mode "commands" needs the first line; sudo_mode "all" needs /usr/bin/sh.
cat > /etc/sudoers.d/tamiz <<'EOF'
tamiz ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/sbin/nginx -T, /usr/sbin/nginx -s reload, /usr/bin/tail -c * -- /var/log/modsec_audit.log, /usr/bin/tail -c * -- /var/log/nginx/error.log, /usr/bin/true, /usr/bin/sh
EOF
chmod 440 /etc/sudoers.d/tamiz && visudo -cf /etc/sudoers.d/tamiz

mkdir -p /run/sshd && ssh-keygen -A >/dev/null
/usr/sbin/sshd -p 2222 -o PasswordAuthentication=no -o PidFile=/run/sshd-lab.pid
nginx -t && (nginx -s reload 2>/dev/null || nginx)
echo "nginx lab ready on :8080, sshd on :2222"
