import re
import math
import socket
import requests
import tldextract
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
import whois


# ─────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────

def count_chars(text, char):
    return text.count(char)

def get_entropy(text):
    """Shannon entropy — measures randomness of a string."""
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 4)


# ─────────────────────────────────────────
# URL STRUCTURE FEATURES
# ─────────────────────────────────────────

def extract_url_features(url):
    features = {}
    parsed = urlparse(url)

    full_url = url
    domain_part = parsed.netloc
    path_part = parsed.path
    query_part = parsed.query
    file_part = path_part.split('/')[-1] if '/' in path_part else ''
    directory_part = '/'.join(path_part.split('/')[:-1]) if '/' in path_part else ''

    # URL-level features
    features['length_url'] = len(full_url)
    features['qty_dot_url'] = count_chars(full_url, '.')
    features['qty_hyphen_url'] = count_chars(full_url, '-')
    features['qty_underline_url'] = count_chars(full_url, '_')
    features['qty_slash_url'] = count_chars(full_url, '/')
    features['qty_questionmark_url'] = count_chars(full_url, '?')
    features['qty_equal_url'] = count_chars(full_url, '=')
    features['qty_at_url'] = count_chars(full_url, '@')
    features['qty_and_url'] = count_chars(full_url, '&')
    features['qty_exclamation_url'] = count_chars(full_url, '!')
    features['qty_space_url'] = count_chars(full_url, ' ')
    features['qty_tilde_url'] = count_chars(full_url, '~')
    features['qty_comma_url'] = count_chars(full_url, ',')
    features['qty_plus_url'] = count_chars(full_url, '+')
    features['qty_asterisk_url'] = count_chars(full_url, '*')
    features['qty_hashtag_url'] = count_chars(full_url, '#')
    features['qty_dollar_url'] = count_chars(full_url, '$')
    features['qty_percent_url'] = count_chars(full_url, '%')
    features['qty_tld_url'] = 1

    # Domain-level features
    features['domain_length'] = len(domain_part)
    features['qty_dot_domain'] = count_chars(domain_part, '.')
    features['qty_hyphen_domain'] = count_chars(domain_part, '-')
    features['qty_underline_domain'] = count_chars(domain_part, '_')
    features['qty_slash_domain'] = count_chars(domain_part, '/')
    features['qty_questionmark_domain'] = count_chars(domain_part, '?')
    features['qty_equal_domain'] = count_chars(domain_part, '=')
    features['qty_at_domain'] = count_chars(domain_part, '@')
    features['qty_and_domain'] = count_chars(domain_part, '&')
    features['qty_exclamation_domain'] = count_chars(domain_part, '!')
    features['qty_space_domain'] = count_chars(domain_part, ' ')
    features['qty_tilde_domain'] = count_chars(domain_part, '~')
    features['qty_comma_domain'] = count_chars(domain_part, ',')
    features['qty_plus_domain'] = count_chars(domain_part, '+')
    features['qty_asterisk_domain'] = count_chars(domain_part, '*')
    features['qty_hashtag_domain'] = count_chars(domain_part, '#')
    features['qty_dollar_domain'] = count_chars(domain_part, '$')
    features['qty_percent_domain'] = count_chars(domain_part, '%')

    # Directory features
    features['directory_length'] = len(directory_part)
    features['qty_dot_directory'] = count_chars(directory_part, '.')
    features['qty_hyphen_directory'] = count_chars(directory_part, '-')
    features['qty_underline_directory'] = count_chars(directory_part, '_')
    features['qty_slash_directory'] = count_chars(directory_part, '/')
    features['qty_questionmark_directory'] = count_chars(directory_part, '?')
    features['qty_equal_directory'] = count_chars(directory_part, '=')
    features['qty_at_directory'] = count_chars(directory_part, '@')
    features['qty_and_directory'] = count_chars(directory_part, '&')
    features['qty_exclamation_directory'] = count_chars(directory_part, '!')
    features['qty_space_directory'] = count_chars(directory_part, ' ')
    features['qty_tilde_directory'] = count_chars(directory_part, '~')
    features['qty_comma_directory'] = count_chars(directory_part, ',')
    features['qty_plus_directory'] = count_chars(directory_part, '+')
    features['qty_asterisk_directory'] = count_chars(directory_part, '*')
    features['qty_hashtag_directory'] = count_chars(directory_part, '#')
    features['qty_dollar_directory'] = count_chars(directory_part, '$')
    features['qty_percent_directory'] = count_chars(directory_part, '%')

    # File features
    features['file_length'] = len(file_part)
    features['qty_dot_file'] = count_chars(file_part, '.')
    features['qty_hyphen_file'] = count_chars(file_part, '-')
    features['qty_underline_file'] = count_chars(file_part, '_')
    features['qty_slash_file'] = count_chars(file_part, '/')
    features['qty_questionmark_file'] = count_chars(file_part, '?')
    features['qty_equal_file'] = count_chars(file_part, '=')
    features['qty_at_file'] = count_chars(file_part, '@')
    features['qty_and_file'] = count_chars(file_part, '&')
    features['qty_exclamation_file'] = count_chars(file_part, '!')
    features['qty_space_file'] = count_chars(file_part, ' ')
    features['qty_tilde_file'] = count_chars(file_part, '~')
    features['qty_comma_file'] = count_chars(file_part, ',')
    features['qty_plus_file'] = count_chars(file_part, '+')
    features['qty_asterisk_file'] = count_chars(file_part, '*')
    features['qty_hashtag_file'] = count_chars(file_part, '#')
    features['qty_dollar_file'] = count_chars(file_part, '$')
    features['qty_percent_file'] = count_chars(file_part, '%')

    # Query string features
    features['params_length'] = len(query_part)
    features['qty_params'] = len(query_part.split('&')) if query_part else 0
    features['qty_dot_params'] = count_chars(query_part, '.')
    features['qty_hyphen_params'] = count_chars(query_part, '-')
    features['qty_underline_params'] = count_chars(query_part, '_')
    features['qty_slash_params'] = count_chars(query_part, '/')
    features['qty_questionmark_params'] = count_chars(query_part, '?')
    features['qty_equal_params'] = count_chars(query_part, '=')
    features['qty_at_params'] = count_chars(query_part, '@')
    features['qty_and_params'] = count_chars(query_part, '&')
    features['qty_exclamation_params'] = count_chars(query_part, '!')
    features['qty_space_params'] = count_chars(query_part, ' ')
    features['qty_tilde_params'] = count_chars(query_part, '~')
    features['qty_comma_params'] = count_chars(query_part, ',')
    features['qty_plus_params'] = count_chars(query_part, '+')
    features['qty_asterisk_params'] = count_chars(query_part, '*')
    features['qty_hashtag_params'] = count_chars(query_part, '#')
    features['qty_dollar_params'] = count_chars(query_part, '$')
    features['qty_percent_params'] = count_chars(query_part, '%')

    # HTTPS
    features['https'] = 1 if parsed.scheme == 'https' else 0

    # IP address in URL
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features['qty_ip_resolved'] = 1 if ip_pattern.search(domain_part) else 0

    # URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly',
                  'short.link', 'buff.ly', 'ift.tt', 'is.gd']
    features['url_shortened'] = 1 if any(s in url.lower() for s in shorteners) else 0

    return features


# ─────────────────────────────────────────
# DNS FEATURES
# ─────────────────────────────────────────

def extract_dns_features(domain):
    features = {}

    # Use Google's public DNS to avoid network restrictions
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    resolver.lifetime = 5

    # Nameservers
    try:
        ns = resolver.resolve(domain, 'NS')
        features['qty_nameservers'] = len(list(ns))
    except:
        features['qty_nameservers'] = 0

    # MX records
    try:
        mx = resolver.resolve(domain, 'MX')
        features['qty_mx_servers'] = len(list(mx))
    except:
        features['qty_mx_servers'] = 0

    # TTL
    try:
        a = resolver.resolve(domain, 'A')
        features['ttl_hostname'] = a.rrset.ttl
    except:
        features['ttl_hostname'] = 0

    # SPF record
    try:
        txt = resolver.resolve(domain, 'TXT')
        spf = any('spf' in str(r).lower() for r in txt)
        features['domain_spf'] = 1 if spf else 0
    except:
        features['domain_spf'] = 0

    # ASN (simplified — use IP)
    try:
        ip = socket.gethostbyname(domain)
        features['asn_ip'] = int(ip.split('.')[0]) * 1000
        features['ip_of_url'] = 1
    except:
        features['asn_ip'] = 0
        features['ip_of_url'] = 0

    return features


# ─────────────────────────────────────────
# WHOIS FEATURES (FIXED)
# ─────────────────────────────────────────

def extract_whois_features(domain):
    features = {}

    try:
        w = whois.whois(domain)
        now = datetime.utcnow()

        # Domain activation (creation date)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if hasattr(creation, 'tzinfo') and creation.tzinfo:
                creation = creation.replace(tzinfo=None)
            features['time_domain_activation'] = (now - creation).days
        else:
            features['time_domain_activation'] = 0

        # Domain expiration
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            if hasattr(expiry, 'tzinfo') and expiry.tzinfo:
                expiry = expiry.replace(tzinfo=None)
            features['time_domain_expiration'] = (expiry - now).days
        else:
            features['time_domain_expiration'] = 0

    except Exception as e:
        print(f"  WHOIS error for {domain}: {e}")
        features['time_domain_activation'] = 0
        features['time_domain_expiration'] = 0

    return features


# ─────────────────────────────────────────
# WEB PRESENCE FEATURES
# ─────────────────────────────────────────

def extract_web_features(url, domain):
    features = {}

    # Redirects
    try:
        response = requests.get(
            url, timeout=5,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        features['qty_redirects'] = len(response.history)
        features['time_response'] = response.elapsed.total_seconds()
    except:
        features['qty_redirects'] = 0
        features['time_response'] = 0

    # Google index — check if domain appears in Google
    try:
        search_url = f"https://www.google.com/search?q=site:{domain}"
        r = requests.get(
            search_url, timeout=5,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        # If Google returns results page (not a captcha/block)
        indexed = 'did not match any documents' not in r.text.lower()
        features['domain_google_index'] = 1 if indexed else 0
        features['url_google_index'] = 1 if indexed else 0
    except:
        features['domain_google_index'] = 0
        features['url_google_index'] = 0

    return features


# ─────────────────────────────────────────
# MAIN EXTRACTOR
# ─────────────────────────────────────────

def extract_all_features(url: str) -> dict:
    """
    Main function — takes a URL string and returns all features.
    """
    print(f"Extracting features for: {url}")

    # Parse domain
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    # Extract all feature groups
    features = {}
    features.update(extract_url_features(url))
    print("  ✓ URL structure features")

    dns_feats = extract_dns_features(domain)
    features.update(dns_feats)
    print("  ✓ DNS features")

    whois_feats = extract_whois_features(domain)
    features.update(whois_feats)
    print("  ✓ WHOIS features")

    web_feats = extract_web_features(url, domain)
    features.update(web_feats)
    print("  ✓ Web presence features")

    print(f"  Total features extracted: {len(features)}")
    return features


# ─────────────────────────────────────────
# TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        "https://github.com",
        "http://paypa1-secure-login.net/verify/account"
    ]

    for url in test_urls:
        print(f"\n{'='*50}")
        features = extract_all_features(url)
        print(f"\nSample features:")
        for k, v in list(features.items())[:10]:
            print(f"  {k}: {v}")