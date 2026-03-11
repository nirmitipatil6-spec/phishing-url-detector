"""
Advanced Phishing Detection Tool
Detects phishing URLs using multiple verification techniques
"""

import re
import requests
from urllib.parse import urlparse
from datetime import datetime
import json
import time
import socket
from typing import Dict, List, Tuple


class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'update', 'confirm', 'secure',
            'urgent', 'suspended', 'click', 'warning', 'alert', 'action',
            'validate', 'authenticate', 'payment', 'bank', 'paypal',
            'amazon', 'apple', 'google', 'confirm-identity', 'reset-password'
        ]

        # Legitimate brand domains - helps prevent false positives
        self.legitimate_brands = {
            'microsoft.com': ['microsoft', 'windows', 'outlook', 'azure'],
            'google.com': ['google', 'gmail', 'youtube'],
            'apple.com': ['apple', 'icloud', 'itunes'],
            'amazon.com': ['amazon', 'aws'],
            'facebook.com': ['facebook', 'fb'],
            'twitter.com': ['twitter', 'x.com'],
            'paypal.com': ['paypal'],
            'adobe.com': ['adobe'],
            'dropbox.com': ['dropbox'],
            'linkedin.com': ['linkedin']
        }

        # Common typosquatting patterns
        self.typosquat_patterns = {
            'o': ['0', 'ο', 'ᴏ'],  # zero, Greek omicron, etc.
            'i': ['1', 'l', '!', 'ı'],  # one, lowercase L, exclamation, dotless i
            'e': ['3'],  # three
            'a': ['4', '@'],  # four, at sign
            's': ['5', '$'],  # five, dollar
            'g': ['9', 'q'],  # nine, q
            'l': ['1', 'i'],  # one, lowercase i
        }

    def analyze_url(self, url: str) -> Dict:
        """Main analysis function that runs all detection methods"""
        results = {
            'url': url,
            'risk_score': 0,
            'risk_level': 'Low',
            'details': [],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        try:
            # Run all detection methods
            self._check_url_length(url, results)
            self._check_https(url, results)
            self._check_url_structure(url, results)
            self._check_suspicious_keywords(url, results)
            self._check_brand_domain_mismatch(url, results)
            self._check_subdomain_abuse(url, results)
            self._check_typosquatting(url, results)
            self._check_domain_age(url, results)
            self._check_redirect_chain(url, results)

        except Exception as e:
            results['error'] = f"Error during analysis: {str(e)}"

        # Calculate final risk level
        results['risk_level'] = self._get_risk_level(results['risk_score'])

        return results

    def _check_url_length(self, url: str, results: Dict):
        """Check if URL is suspiciously long"""
        if len(url) > 75:
            risk = min(20, (len(url) - 75) // 10)
            results['risk_score'] += risk
            results['details'].append({
                'check': 'URL Length',
                'status': 'SUSPICIOUS',
                'reason': f'URL is unusually long ({len(url)} chars)',
                'risk': risk
            })
        else:
            results['details'].append({
                'check': 'URL Length',
                'status': 'SAFE',
                'reason': f'URL length is normal ({len(url)} chars)',
                'risk': 0
            })

    def _check_https(self, url: str, results: Dict):
        """Check HTTPS usage"""
        if not url.startswith('https://'):
            if url.startswith('http://'):
                results['risk_score'] += 25
                results['details'].append({
                    'check': 'HTTPS Protocol',
                    'status': 'SUSPICIOUS',
                    'reason': 'URL uses insecure HTTP instead of HTTPS',
                    'risk': 25
                })
            else:
                results['risk_score'] += 30
                results['details'].append({
                    'check': 'HTTPS Protocol',
                    'status': 'CRITICAL',
                    'reason': 'URL has no recognized protocol',
                    'risk': 30
                })
        else:
            results['details'].append({
                'check': 'HTTPS Protocol',
                'status': 'SAFE',
                'reason': 'URL uses secure HTTPS protocol',
                'risk': 0
            })

    def _check_url_structure(self, url: str, results: Dict):
        """Check basic URL structure validity"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                results['risk_score'] += 20
                results['details'].append({
                    'check': 'URL Structure',
                    'status': 'INVALID',
                    'reason': 'URL has invalid structure or missing domain',
                    'risk': 20
                })
                return

            results['details'].append({
                'check': 'URL Structure',
                'status': 'VALID',
                'reason': f'Domain: {parsed.netloc}',
                'risk': 0
            })
        except Exception as e:
            results['risk_score'] += 25
            results['details'].append({
                'check': 'URL Structure',
                'status': 'INVALID',
                'reason': f'URL parsing failed: {str(e)}',
                'risk': 25
            })

    def _check_suspicious_keywords(self, url: str, results: Dict):
        """Check for suspicious keywords in URL"""
        url_lower = url.lower()
        found_keywords = []
        risk = 0

        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                found_keywords.append(keyword)
                risk += 5

        if found_keywords:
            risk = min(risk, 20)  # Cap at 20
            results['risk_score'] += risk
            results['details'].append({
                'check': 'Suspicious Keywords',
                'status': 'WARNING',
                'reason': f'Found suspicious keywords: {", ".join(found_keywords)}',
                'risk': risk
            })
        else:
            results['details'].append({
                'check': 'Suspicious Keywords',
                'status': 'SAFE',
                'reason': 'No suspicious keywords detected',
                'risk': 0
            })

    def _check_brand_domain_mismatch(self, url: str, results: Dict):
        """Check for brand-domain mismatches"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')

        mismatches = []
        for brand_domain, brand_keywords in self.legitimate_brands.items():
            # Check if URL mentions the brand but doesn't use the real domain
            brand_name = brand_domain.split('.')[0]

            if any(keyword in url.lower() for keyword in brand_keywords):
                if domain != brand_domain and not domain.endswith(brand_domain):
                    mismatches.append({
                        'brand': brand_name.upper(),
                        'real_domain': brand_domain,
                        'found_domain': domain
                    })

        if mismatches:
            risk = min(30 * len(mismatches), 35)
            results['risk_score'] += risk
            mismatch_text = '; '.join([
                f"{m['brand']} content but domain is {m['found_domain']} (not {m['real_domain']})"
                for m in mismatches
            ])
            results['details'].append({
                'check': 'Brand-Domain Mismatch',
                'status': 'CRITICAL',
                'reason': mismatch_text,
                'risk': risk
            })
        else:
            results['details'].append({
                'check': 'Brand-Domain Mismatch',
                'status': 'SAFE',
                'reason': 'No brand-domain mismatches detected',
                'risk': 0
            })

    def _check_subdomain_abuse(self, url: str, results: Dict):
        """Check for suspicious subdomain usage (e.g., google.com.attacker.com)"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Check for well-known legitimate domains embedded in subdomains
        suspicious_subdomains = []
        for brand_domain in self.legitimate_brands.keys():
            if brand_domain in domain and not domain.endswith(brand_domain):
                suspicious_subdomains.append(brand_domain)

        if suspicious_subdomains:
            results['risk_score'] += 35
            results['details'].append({
                'check': 'Subdomain Abuse',
                'status': 'CRITICAL',
                'reason': f'Legitimate domain names in subdomain: {", ".join(suspicious_subdomains)}. '
                          f'Actual domain: {domain}',
                'risk': 35
            })

        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            results['risk_score'] += 15
            results['details'].append({
                'check': 'Subdomain Count',
                'status': 'SUSPICIOUS',
                'reason': f'Unusually high number of subdomains ({subdomain_count} dots)',
                'risk': 15
            })
        elif suspicious_subdomains or subdomain_count == 0:
            if 'Subdomain Abuse' not in [d['check'] for d in results['details']]:
                results['details'].append({
                    'check': 'Subdomain Abuse',
                    'status': 'SAFE',
                    'reason': 'No subdomain abuse detected',
                    'risk': 0
                })

    def _check_typosquatting(self, url: str, results: Dict):
        """Check for typosquatting attempts"""
        domain = urlparse(url).netloc.lower().replace('www.', '')
        domain_name = domain.split('.')[0]

        typosquat_hits = []

        for brand_domain, brand_keywords in self.legitimate_brands.items():
            brand_name = brand_domain.split('.')[0]

            # Check if domain is similar but not exact
            if brand_name.lower() != domain_name:
                # Check for character substitutions
                for original_char, replacements in self.typosquat_patterns.items():
                    for replacement in replacements:
                        typo_variant = brand_name.replace(original_char, replacement)
                        if typo_variant == domain_name:
                            typosquat_hits.append({
                                'real_brand': brand_name,
                                'typo_found': domain_name,
                                'substitution': f'{original_char} → {replacement}'
                            })

                # Levenshtein-like simple distance check
                if len(brand_name) == len(domain_name):
                    diff_count = sum(1 for a, b in zip(brand_name, domain_name) if a != b)
                    if diff_count == 1:  # Only 1 character different
                        typosquat_hits.append({
                            'real_brand': brand_name,
                            'typo_found': domain_name,
                            'substitution': 'Single character difference'
                        })

        if typosquat_hits:
            risk = min(35, 20 * len(typosquat_hits))
            results['risk_score'] += risk
            hits_text = '; '.join([
                f"{h['real_brand']} → {h['typo_found']} ({h['substitution']})"
                for h in typosquat_hits
            ])
            results['details'].append({
                'check': 'Typosquatting Detection',
                'status': 'CRITICAL',
                'reason': f'Typosquatting patterns detected: {hits_text}',
                'risk': risk
            })
        else:
            results['details'].append({
                'check': 'Typosquatting Detection',
                'status': 'SAFE',
                'reason': 'No typosquatting patterns detected',
                'risk': 0
            })

    def _check_domain_age(self, url: str, results: Dict):
        """Check domain age via WHOIS lookup (simulated with DNS)"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.replace('www.', '')

            # Try to resolve domain
            try:
                ip_address = socket.gethostbyname(domain)
                results['details'].append({
                    'check': 'Domain Age & WHOIS',
                    'status': 'RESOLVED',
                    'reason': f'Domain resolves to IP: {ip_address} (Use WHOIS service for detailed age info)',
                    'risk': 0,
                    'data': {'ip': ip_address}
                })
            except socket.gaierror:
                results['risk_score'] += 20
                results['details'].append({
                    'check': 'Domain Age & WHOIS',
                    'status': 'CRITICAL',
                    'reason': 'Domain does not resolve or does not exist',
                    'risk': 20
                })
        except Exception as e:
            results['details'].append({
                'check': 'Domain Age & WHOIS',
                'status': 'ERROR',
                'reason': f'Could not check domain: {str(e)}',
                'risk': 0
            })

    def _check_redirect_chain(self, url: str, results: Dict):
        """Check for suspicious redirect chains"""
        try:
            # Set a timeout and follow redirects
            response = requests.head(url, allow_redirects=False, timeout=5,
                                     headers={'User-Agent': 'Mozilla/5.0'})

            redirects = [url]
            current_url = url
            redirect_count = 0

            while response.status_code in [301, 302, 303, 307, 308] and redirect_count < 10:
                current_url = response.headers.get('Location')
                if not current_url:
                    break

                # Handle relative redirects
                if not current_url.startswith('http'):
                    current_url = urlparse(url).scheme + '://' + urlparse(url).netloc + current_url

                redirects.append(current_url)
                redirect_count += 1

                try:
                    response = requests.head(current_url, allow_redirects=False, timeout=5,
                                             headers={'User-Agent': 'Mozilla/5.0'})
                except:
                    break

            if redirect_count >= 3:
                results['risk_score'] += 20
                results['details'].append({
                    'check': 'Redirect Chain Detection',
                    'status': 'SUSPICIOUS',
                    'reason': f'Multiple redirects detected ({redirect_count} redirects)',
                    'risk': 20,
                    'data': {'redirect_chain': redirects[:5]}  # Show first 5
                })
            elif redirect_count > 0:
                results['details'].append({
                    'check': 'Redirect Chain Detection',
                    'status': 'WARNING',
                    'reason': f'{redirect_count} redirect(s) detected',
                    'risk': 5,
                    'data': {'redirect_chain': redirects}
                })
            else:
                results['details'].append({
                    'check': 'Redirect Chain Detection',
                    'status': 'SAFE',
                    'reason': 'No suspicious redirects detected',
                    'risk': 0
                })

        except requests.exceptions.Timeout:
            results['details'].append({
                'check': 'Redirect Chain Detection',
                'status': 'TIMEOUT',
                'reason': 'Could not reach URL within timeout period',
                'risk': 0
            })
        except requests.exceptions.ConnectionError:
            results['details'].append({
                'check': 'Redirect Chain Detection',
                'status': 'UNREACHABLE',
                'reason': 'URL is not reachable',
                'risk': 0
            })
        except Exception as e:
            results['details'].append({
                'check': 'Redirect Chain Detection',
                'status': 'ERROR',
                'reason': f'Could not check redirects: {str(e)}',
                'risk': 0
            })

    def _get_risk_level(self, risk_score: int) -> str:
        """Determine risk level based on score"""
        if risk_score >= 70:
            return 'CRITICAL'
        elif risk_score >= 50:
            return 'HIGH'
        elif risk_score >= 30:
            return 'MEDIUM'
        elif risk_score >= 15:
            return 'LOW'
        else:
            return 'SAFE'


def main():
    detector = PhishingDetector()

    print("\n" + "=" * 70)
    print("         ADVANCED PHISHING DETECTION TOOL")
    print("=" * 70)

    while True:
        print("\n1. Analyze URL")
        print("2. Exit")
        choice = input("\nEnter your choice (1-2): ").strip()

        if choice == '1':
            url = input("\nEnter URL to analyze: ").strip()

            if not url:
                print("Error: URL cannot be empty!")
                continue

            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            print("\n" + "-" * 70)
            print("ANALYZING URL...")
            print("-" * 70)

            results = detector.analyze_url(url)

            # Display results
            print(f"\nURL: {results['url']}")
            print(f"Risk Score: {results['risk_score']}/100")
            print(f"Risk Level: {results['risk_level']}")
            print(f"Timestamp: {results['timestamp']}\n")

            print("DETAILED ANALYSIS:")
            print("-" * 70)

            for detail in results['details']:
                status_color = detail['status']
                print(f"\n✓ {detail['check']}")
                print(f"  Status: {status_color}")
                print(f"  Reason: {detail['reason']}")
                print(f"  Risk Points: +{detail['risk']}")

                if 'data' in detail and detail['data']:
                    if 'redirect_chain' in detail['data']:
                        print(f"  Redirects: {' → '.join(detail['data']['redirect_chain'][:3])}")
                    elif 'ip' in detail['data']:
                        print(f"  IP Address: {detail['data']['ip']}")

            print("\n" + "=" * 70)

            if results.get('error'):
                print(f"Error: {results['error']}")

        elif choice == '2':
            print("\nThank you for using Phishing Detection Tool!")
            break
        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()