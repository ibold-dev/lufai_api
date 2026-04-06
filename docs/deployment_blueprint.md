# Hardened Production Deployment: lufai_api (AWS EC2 + Nginx + SSL)

This guide provides a copy-pasteable, 100% correct, and **highly secured** deployment strategy. It uses a single instance architecture (Low-Cost) but adds several layers of defense-in-depth.

---

## Phase 1: Managed Infrastructure (AWS Console)

1.  **EC2 Launch**:
    -   **AMI**: Ubuntu 24.04 LTS (HVM)
    -   **Instance**: `t3.medium` (Minimum 4GB RAM highly recommended for compilation).
    -   **Key Pair**: Create one and secure it locally (`chmod 400 key.pem`).

2.  **Security Group** (Firewall at the Cloud Edge):
    -   **Inbound Rules**: 
        -   Port 22 (SSH): Allow FROM YOUR IP ONLY.
        -   Port 80 (HTTP): Allow FROM Anywhere.
        -   Port 443 (HTTPS): Allow FROM Anywhere.

---

## Phase 2: OS Hardening (SSH into the Instance)

Execute as `ubuntu` user:

```bash
# 1. Update system and install security suites
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y fail2ban unattended-upgrades ufw docker.io docker-compose-v2 nginx certbot python3-certbot-nginx

# 2. Configure Firewall (UFW)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# 3. Secure SSH Configuration
# (WARNING: Ensure you have your SSH key working before this!)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# 4. Enable Automated Security Updates
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## Phase 3: Project Configuration & Security Secrets

Clone the project and prepare the production environment:

```bash
git clone https://github.com/BOLD-DEV/lufai_api.git
cd lufai_api
```

### Generate Production Secrets
Generate high-entropy strings for your credentials:
```bash
# Generate DB Password
DB_PWD=$(openssl rand -base64 32)
# Generate JWT Secret (High Entropy)
JWT_SEC=$(openssl rand -base64 64)

echo "DB_PASSWORD=$DB_PWD" >> .env
echo "JWT_SECRET=$JWT_SEC" >> .env
echo "DB_USER=lufai_prod_admin" >> .env
echo "DB_NAME=lufai_production" >> .env
echo "JWT_ISSUER=api.yourdomain.com" >> .env
echo "RUST_LOG=info" >> .env
```
> [!CAUTION]
> Manually edit your `.env` to include any other keys (Paystack, Google OAuth) if needed.

---

## Phase 4: Production-Hardened Nginx

We disable deprecated protocols and enable strong security headers.

1. Create the site file: `sudo nano /etc/nginx/sites-available/lufai_api`
2. Paste the following:

```nginx
# Secure Rate Limiting
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

server {
    server_name api.yourdomain.com; # <--- Replace this

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Referrer-Policy strict-origin-when-cross-origin;
    
    # Hide Nginx version
    server_tokens off;

    location / {
        limit_req zone=mylimit burst=20 nodelay;
        
        proxy_pass http://127.0.0.1:3000; # Forward to the hidden Docker port
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Deny access to hidden files (.env, .git)
    location ~ /\. {
        deny all;
    }
}
```

Activate and obtain SSL:
```bash
sudo ln -s /etc/nginx/sites-available/lufai_api /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
sudo certbot --nginx -d api.yourdomain.com
```

---

## Phase 5: Zero-Trust Docker Activation

Using the provided `docker-compose.prod.yml`, start the services:

```bash
# Ensure the DB password matches your .env
# Start in detached mode
sudo docker compose -f docker-compose.prod.yml up -d --build
```

---

## 100% Correctness Checklist (Operational Check)

1.  **Health Check**: `curl -I https://api.yourdomain.com/healthz` (Should return 200 OK).
2.  **Internal isolation**: Try `curl http://localhost:5432`. It SHOULD fail (DB is private to Docker internal network).
3.  **Logs**: `sudo docker compose -f docker-compose.prod.yml logs -f api`.
4.  **Persistent Backups**: The database data is stored in the `postgres_data` Docker volume.

### Operational Backup Script (Cron)
Create a daily backup:
```bash
# Run every night at 2:00 AM
0 2 * * * sudo docker exec -t lufai_api-postgres-1 pg_dump -U lufai_prod_admin lufai_production > /home/ubuntu/backups/db_$(date +\%F).sql
```
