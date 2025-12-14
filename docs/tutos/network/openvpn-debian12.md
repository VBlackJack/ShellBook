---
tags:
  - tutos
  - network
  - openvpn
  - vpn
  - security
  - debian
---

# OpenVPN sur Debian 12

Installation de **OpenVPN** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| OpenVPN | 2.5+ |
| Easy-RSA | 3.x |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
apt update
apt install -y openvpn easy-rsa
```

---

## 2. Configuration PKI

```bash
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

cat > vars << 'EOF'
set_var EASYRSA_REQ_COUNTRY    "FR"
set_var EASYRSA_REQ_PROVINCE   "IDF"
set_var EASYRSA_REQ_CITY       "Paris"
set_var EASYRSA_REQ_ORG        "MyOrg"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    365
EOF

./easyrsa init-pki
./easyrsa build-ca nopass
```

---

## 3. Certificats serveur

```bash
./easyrsa gen-req server nopass
./easyrsa sign-req server server
./easyrsa gen-dh
openvpn --genkey secret /etc/openvpn/ta.key

cp pki/ca.crt /etc/openvpn/
cp pki/issued/server.crt /etc/openvpn/
cp pki/private/server.key /etc/openvpn/
cp pki/dh.pem /etc/openvpn/
```

---

## 4. Configuration serveur

```bash
cat > /etc/openvpn/server.conf << 'EOF'
port 1194
proto udp
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

push "route 192.168.1.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"

keepalive 10 120
cipher AES-256-GCM
auth SHA256

user nobody
group nogroup
persist-key
persist-tun

status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3
EOF
```

---

## 5. IP Forwarding et NAT

```bash
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

# NAT avec iptables
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
apt install -y iptables-persistent
netfilter-persistent save
```

---

## 6. Firewall

```bash
ufw allow 1194/udp
ufw reload
```

---

## 7. Démarrer

```bash
systemctl enable --now openvpn-server@server
```

---

## 8. Créer un client

```bash
cd /etc/openvpn/easy-rsa
./easyrsa gen-req client1 nopass
./easyrsa sign-req client client1

mkdir -p /etc/openvpn/clients/client1
```

### Fichier .ovpn unifié

```bash
cat > /etc/openvpn/clients/client1/client1.ovpn << 'EOF'
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3
key-direction 1

<ca>
EOF

cat pki/ca.crt >> /etc/openvpn/clients/client1/client1.ovpn
echo "</ca>" >> /etc/openvpn/clients/client1/client1.ovpn
echo "<cert>" >> /etc/openvpn/clients/client1/client1.ovpn
cat pki/issued/client1.crt >> /etc/openvpn/clients/client1/client1.ovpn
echo "</cert>" >> /etc/openvpn/clients/client1/client1.ovpn
echo "<key>" >> /etc/openvpn/clients/client1/client1.ovpn
cat pki/private/client1.key >> /etc/openvpn/clients/client1/client1.ovpn
echo "</key>" >> /etc/openvpn/clients/client1/client1.ovpn
echo "<tls-auth>" >> /etc/openvpn/clients/client1/client1.ovpn
cat /etc/openvpn/ta.key >> /etc/openvpn/clients/client1/client1.ovpn
echo "</tls-auth>" >> /etc/openvpn/clients/client1/client1.ovpn
```

---

## 9. Révoquer un certificat

```bash
cd /etc/openvpn/easy-rsa
./easyrsa revoke client1
./easyrsa gen-crl
cp pki/crl.pem /etc/openvpn/
```

Ajouter dans server.conf : `crl-verify crl.pem`

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | epel + openvpn | openvpn |
| Group nobody | nobody | nogroup |
| Easy-RSA | /usr/share/easy-rsa/3 | make-cadir |
| Firewall | firewalld | ufw + iptables |

---

## Commandes

```bash
# Status
systemctl status openvpn-server@server

# Logs
journalctl -u openvpn-server@server -f
tail -f /var/log/openvpn.log

# Clients connectés
cat /var/log/openvpn-status.log
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
