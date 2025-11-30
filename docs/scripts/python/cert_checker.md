---
tags:
  - scripts
  - python
  - ssl
  - certificates
  - security
  - monitoring
---

# cert_checker.py

:material-star::material-star: **Niveau : Intermédiaire**

Vérification des certificats SSL/TLS pour plusieurs domaines.

---

## Description

Ce script vérifie les certificats SSL/TLS :
- Validité et expiration
- Chaîne de certificats
- Correspondance CN/SAN avec le domaine
- Algorithmes de signature
- Export des résultats en JSON/CSV

---

## Prérequis

```bash
pip install cryptography requests
```

---

## Script

```python
#!/usr/bin/env python3
"""
cert_checker.py - Vérification des certificats SSL/TLS
"""

import ssl
import socket
import json
import csv
import sys
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


@dataclass
class CertificateInfo:
    """Information sur un certificat"""
    domain: str
    port: int
    valid: bool
    issuer: str
    subject: str
    serial_number: str
    not_before: str
    not_after: str
    days_until_expiry: int
    expired: bool
    expiring_soon: bool
    san_domains: List[str]
    signature_algorithm: str
    public_key_type: str
    public_key_bits: int
    chain_length: int
    error: Optional[str] = None


class CertificateChecker:
    """Vérificateur de certificats SSL/TLS"""

    def __init__(self, timeout: int = 10, warning_days: int = 30):
        self.timeout = timeout
        self.warning_days = warning_days

    def check_certificate(self, domain: str, port: int = 443) -> CertificateInfo:
        """Vérifie le certificat d'un domaine"""
        try:
            # Connexion SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_OPTIONAL

            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

                    if CRYPTOGRAPHY_AVAILABLE and cert_der:
                        return self._parse_cert_cryptography(domain, port, cert_der, cert_dict)
                    elif cert_dict:
                        return self._parse_cert_stdlib(domain, port, cert_dict)
                    else:
                        return self._error_result(domain, port, "No certificate received")

        except socket.timeout:
            return self._error_result(domain, port, "Connection timeout")
        except socket.gaierror as e:
            return self._error_result(domain, port, f"DNS resolution failed: {e}")
        except ssl.SSLError as e:
            return self._error_result(domain, port, f"SSL error: {e}")
        except ConnectionRefusedError:
            return self._error_result(domain, port, "Connection refused")
        except Exception as e:
            return self._error_result(domain, port, f"Error: {e}")

    def _parse_cert_cryptography(self, domain: str, port: int,
                                  cert_der: bytes, cert_dict: dict) -> CertificateInfo:
        """Parse le certificat avec cryptography"""
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Dates
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days_until_expiry = (not_after - now).days

        # Subject et Issuer
        subject = self._get_cn(cert.subject)
        issuer = self._get_cn(cert.issuer)

        # SAN (Subject Alternative Names)
        san_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_domains = [name.value for name in san_ext.value
                          if isinstance(name, x509.DNSName)]
        except x509.ExtensionNotFound:
            pass

        # Clé publique
        public_key = cert.public_key()
        key_type = type(public_key).__name__.replace('_', ' ')
        key_bits = public_key.key_size if hasattr(public_key, 'key_size') else 0

        return CertificateInfo(
            domain=domain,
            port=port,
            valid=True,
            issuer=issuer,
            subject=subject,
            serial_number=format(cert.serial_number, 'X'),
            not_before=not_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
            not_after=not_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
            days_until_expiry=days_until_expiry,
            expired=days_until_expiry < 0,
            expiring_soon=0 <= days_until_expiry <= self.warning_days,
            san_domains=san_domains,
            signature_algorithm=cert.signature_algorithm_oid._name,
            public_key_type=key_type,
            public_key_bits=key_bits,
            chain_length=len(cert_dict.get('chain', [])) if cert_dict else 1
        )

    def _parse_cert_stdlib(self, domain: str, port: int, cert_dict: dict) -> CertificateInfo:
        """Parse le certificat avec la stdlib"""
        # Dates
        not_before = datetime.strptime(cert_dict['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.utcnow()
        days_until_expiry = (not_after - now).days

        # Subject et Issuer
        subject = dict(x[0] for x in cert_dict.get('subject', ()))
        issuer = dict(x[0] for x in cert_dict.get('issuer', ()))

        # SAN
        san_domains = []
        for san_type, san_value in cert_dict.get('subjectAltName', ()):
            if san_type == 'DNS':
                san_domains.append(san_value)

        return CertificateInfo(
            domain=domain,
            port=port,
            valid=True,
            issuer=issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
            subject=subject.get('commonName', 'Unknown'),
            serial_number=str(cert_dict.get('serialNumber', '')),
            not_before=not_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
            not_after=not_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
            days_until_expiry=days_until_expiry,
            expired=days_until_expiry < 0,
            expiring_soon=0 <= days_until_expiry <= self.warning_days,
            san_domains=san_domains,
            signature_algorithm='Unknown',
            public_key_type='Unknown',
            public_key_bits=0,
            chain_length=1
        )

    def _get_cn(self, name: x509.Name) -> str:
        """Extrait le Common Name"""
        try:
            cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn:
                return cn[0].value
        except Exception:
            pass
        return str(name)

    def _error_result(self, domain: str, port: int, error: str) -> CertificateInfo:
        """Retourne un résultat d'erreur"""
        return CertificateInfo(
            domain=domain,
            port=port,
            valid=False,
            issuer='',
            subject='',
            serial_number='',
            not_before='',
            not_after='',
            days_until_expiry=-1,
            expired=True,
            expiring_soon=False,
            san_domains=[],
            signature_algorithm='',
            public_key_type='',
            public_key_bits=0,
            chain_length=0,
            error=error
        )


class OutputFormatter:
    """Formateur de sortie"""

    @staticmethod
    def print_console(results: List[CertificateInfo], verbose: bool = False):
        """Affiche les résultats en console"""
        # Couleurs ANSI
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        GRAY = '\033[90m'
        RESET = '\033[0m'
        BOLD = '\033[1m'

        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{GREEN}  SSL/TLS CERTIFICATE CHECK{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Domains checked: {len(results)}")
        print(f"{CYAN}{'-'*70}{RESET}\n")

        for cert in results:
            # Status icon
            if cert.error:
                status = f"{RED}[FAIL]{RESET}"
            elif cert.expired:
                status = f"{RED}[EXPIRED]{RESET}"
            elif cert.expiring_soon:
                status = f"{YELLOW}[WARNING]{RESET}"
            else:
                status = f"{GREEN}[OK]{RESET}"

            print(f"{status} {BOLD}{cert.domain}:{cert.port}{RESET}")

            if cert.error:
                print(f"    {RED}Error: {cert.error}{RESET}")
                continue

            # Expiration
            if cert.expired:
                print(f"    {RED}EXPIRED {abs(cert.days_until_expiry)} days ago{RESET}")
            elif cert.expiring_soon:
                print(f"    {YELLOW}Expires in {cert.days_until_expiry} days{RESET}")
            else:
                print(f"    {GRAY}Expires in {cert.days_until_expiry} days ({cert.not_after}){RESET}")

            if verbose:
                print(f"    {GRAY}Subject: {cert.subject}{RESET}")
                print(f"    {GRAY}Issuer: {cert.issuer}{RESET}")
                print(f"    {GRAY}Serial: {cert.serial_number[:20]}...{RESET}")
                print(f"    {GRAY}Algorithm: {cert.signature_algorithm}{RESET}")
                print(f"    {GRAY}Key: {cert.public_key_type} {cert.public_key_bits} bits{RESET}")
                if cert.san_domains:
                    print(f"    {GRAY}SAN: {', '.join(cert.san_domains[:5])}"
                          f"{'...' if len(cert.san_domains) > 5 else ''}{RESET}")
            print()

        # Résumé
        ok = sum(1 for c in results if c.valid and not c.expired and not c.expiring_soon)
        warning = sum(1 for c in results if c.expiring_soon)
        failed = sum(1 for c in results if c.error or c.expired)

        print(f"{CYAN}{'='*70}{RESET}")
        print(f"  {GREEN}Valid: {ok}{RESET}  {YELLOW}Expiring soon: {warning}{RESET}  {RED}Failed/Expired: {failed}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}\n")

    @staticmethod
    def export_json(results: List[CertificateInfo], filepath: str):
        """Exporte en JSON"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'certificates': [asdict(cert) for cert in results]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Results exported to {filepath}")

    @staticmethod
    def export_csv(results: List[CertificateInfo], filepath: str):
        """Exporte en CSV"""
        if not results:
            return

        fieldnames = list(asdict(results[0]).keys())
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for cert in results:
                row = asdict(cert)
                row['san_domains'] = ';'.join(row['san_domains'])
                writer.writerow(row)
        print(f"Results exported to {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description='Check SSL/TLS certificates for domains'
    )
    parser.add_argument(
        'domains',
        nargs='*',
        help='Domains to check (format: domain or domain:port)'
    )
    parser.add_argument(
        '-f', '--file',
        help='File containing domains (one per line)'
    )
    parser.add_argument(
        '-w', '--warning-days',
        type=int,
        default=30,
        help='Days before expiry to trigger warning (default: 30)'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='Connection timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--json',
        metavar='FILE',
        help='Export results to JSON file'
    )
    parser.add_argument(
        '--csv',
        metavar='FILE',
        help='Export results to CSV file'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Only output errors and warnings'
    )

    args = parser.parse_args()

    # Collecter les domaines
    domains = []

    for d in args.domains:
        if ':' in d:
            domain, port = d.rsplit(':', 1)
            domains.append((domain, int(port)))
        else:
            domains.append((d, 443))

    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if ':' in line:
                        domain, port = line.rsplit(':', 1)
                        domains.append((domain, int(port)))
                    else:
                        domains.append((line, 443))

    if not domains:
        parser.print_help()
        sys.exit(1)

    # Vérifier les certificats
    checker = CertificateChecker(
        timeout=args.timeout,
        warning_days=args.warning_days
    )

    results = []
    for domain, port in domains:
        result = checker.check_certificate(domain, port)
        results.append(result)

    # Affichage
    if not args.quiet:
        OutputFormatter.print_console(results, args.verbose)
    else:
        # Mode quiet: seulement les problèmes
        for cert in results:
            if cert.error or cert.expired or cert.expiring_soon:
                if cert.error:
                    print(f"FAIL {cert.domain}:{cert.port} - {cert.error}")
                elif cert.expired:
                    print(f"EXPIRED {cert.domain}:{cert.port} - {abs(cert.days_until_expiry)} days ago")
                else:
                    print(f"WARNING {cert.domain}:{cert.port} - expires in {cert.days_until_expiry} days")

    # Export
    if args.json:
        OutputFormatter.export_json(results, args.json)
    if args.csv:
        OutputFormatter.export_csv(results, args.csv)

    # Code de sortie
    if any(c.error or c.expired for c in results):
        sys.exit(2)
    elif any(c.expiring_soon for c in results):
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
```

---

## Utilisation

```bash
# Vérifier un domaine
python cert_checker.py example.com

# Plusieurs domaines
python cert_checker.py google.com github.com:443 smtp.gmail.com:465

# Depuis un fichier
python cert_checker.py -f domains.txt

# Mode verbeux
python cert_checker.py -v example.com

# Export JSON
python cert_checker.py --json results.json example.com

# Mode monitoring (quiet)
python cert_checker.py -q -w 60 example.com
```

---

## Fichier domains.txt

```text
# Domaines à vérifier
google.com
github.com
# SMTP avec port
smtp.gmail.com:465
```

---

## Voir Aussi

- [kubernetes_health.py](kubernetes_health.md)
- [docker_health.py](docker_health.md)
