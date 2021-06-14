from __future__ import print_function

from socket import gethostbyname, gaierror
from sys import version_info, exit

import click
import requests
from requests import get, exceptions
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if version_info[0] == 2:
    pass
elif version_info[0] == 3:
    pass

import logging
import tldextract
import json
import pythonwhois

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)

logger = logging.getLogger('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

__author__ = "Bharath(github.com/yamakira)"
__version__ = "0.0.1"
__purpose__ = '''Parse and print domain names from Content Security Policy(CSP) header'''


class Domain:
    def __init__(self, domain=None, apex_domain=None, available=None, ip=None, raw_csp_url=None):
        self.domain = domain
        self.apex_domain = apex_domain
        self.available = available
        self.ip = ip
        self.raw_csp_url = raw_csp_url


def clean_domains(domains):
    for domain in domains:
        ext = tldextract.extract(str(domain.raw_csp_url))
        # If subdomain is wildcard or empty
        if ext[0] in ['*', '']:
            # Join all but the subdomain (a wildcard or empty)
            domain.domain = '.'.join(ext[1:])
        else:
            domain.domain = '.'.join(ext)
        domain.apex_domain = ".".join(tldextract.extract(domain.domain)[1:])
    return domains


def get_csp_header(url):
    try:
        # logger.info("[+] Fetching headers for {}".format(url))
        r = get(url, verify=False)
    except exceptions.RequestException as e:
        print(e)
        exit(1)

    if 'Content-Security-Policy' in r.headers:
        csp_header = r.headers['Content-Security-Policy']
        return csp_header
    elif 'content-security-policy-report-only' in r.headers:
        csp_header = r.headers["content-security-policy-report-only"]
        return csp_header
    else:
        logger.info("[+] {} doesn't support CSP header".format(url))
        exit(1)


def get_domains(csp_header):
    domains = []
    csp_header_values = csp_header.split(" ")
    for line in csp_header_values:
        if "." in line:
            line = line.replace(";", "")
            domains.append(Domain(raw_csp_url=line))
        else:
            pass
    return clean_domains(domains)


def resolve_domains(domains):
    # To resolve the domains, we need to clean them
    for domain in clean_domains(domains):
        try:
            ip_address = gethostbyname(domain.domain)
            domain.ip = ip_address
            print("\033[92m{0:<30} - {1:20}\033[1;m".format(domain.domain, ip_address.rstrip("\n\r")))
        except gaierror as e:
            print("\033[93m{0:<30} - {1:20}\033[1;m".format(domain.domain, "No A record exists"), end=''),
            print(e.message)
    return domains


def check_whois_domains(domains):
    # TODO - Check apex domains once instead of for each domain stored (the same apex domain may appear several times)
    for domain in domains:
        details = pythonwhois.get_whois(domain.apex_domain)
        if details.get('status') is None:
            print("[!] Domain available for registering: {}".format(domain.apex_domain))
            domain.available = True
        else:
            print("[i] Domain registered: {}".format(domain.apex_domain))
            domain.available = False
    return domains


@click.command()
@click.option('--url', '-u', required=True,
              help='Url to retrieve the CSP header from')
@click.option('--resolve/--no-resolve', '-r', default=False,
              help='Enable/Disable DNS resolution')
@click.option('--check-whois/--no-check-whois', '--whois', default=False,
              help='Check for domain availability')
@click.option('--output', '-o', default=False,
              help='Save results into a json file')
def main(url, resolve, check_whois, output):
    csp_header = get_csp_header(url)
    # Retrieve list of domains "clean" or not
    domains = get_domains(csp_header)
    if resolve:
        domains = resolve_domains(domains)
    if check_whois:
        domains = check_whois_domains(domains)
    if output:
        with open(output, 'w') as outfile:
            json.dump(dict(domains=[ob.__dict__ for ob in domains]), outfile, sort_keys=True, indent=4)


if __name__ == '__main__':
    main()

t = {'X-Amz-Cf-Pop': 'VIE50-C2', 'X-XSS-Protection': '1; mode=block', 'X-Cache': 'Hit from cloudfront',
     'X-Content-Type-Options': 'nosniff', 'Content-Encoding': 'gzip', 'Transfer-Encoding': 'chunked', 'Age': '80244',
     'Strict-Transport-Security': 'max-age=63072000', 'Vary': 'Accept-Encoding', 'Server': 'AmazonS3',
     'Content-Security-Policy-Report-Only': "default-src 'self'; script-src 'report-sample' 'self' *.speedcurve.com 'sha256-q7cJjDqNO2e1L5UltvJ1LhvnYN7yJXgGO7b6h9xkL1o=' www.google-analytics.com/analytics.js 'sha256-JEt9Nmc3BP88wxuTZm9aKNu87vEgGmKW1zzy/vb1KPs=' polyfill.io/v3/polyfill.min.js assets.codepen.io production-assets.codepen.io; script-src-elem 'report-sample' 'self' *.speedcurve.com 'sha256-q7cJjDqNO2e1L5UltvJ1LhvnYN7yJXgGO7b6h9xkL1o=' www.google-analytics.com/analytics.js 'sha256-JEt9Nmc3BP88wxuTZm9aKNu87vEgGmKW1zzy/vb1KPs=' polyfill.io/v3/polyfill.min.js assets.codepen.io production-assets.codepen.io; style-src 'report-sample' 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; connect-src 'self' www.google-analytics.com stats.g.doubleclick.net; font-src 'self'; frame-src 'self' interactive-examples.mdn.mozilla.net mdn.github.io yari-demos.prod.mdn.mozit.cloud mdn.mozillademos.org yari-demos.stage.mdn.mozit.cloud jsfiddle.net www.youtube-nocookie.com codepen.io; img-src 'self' *.githubusercontent.com *.googleusercontent.com lux.speedcurve.com mdn.mozillademos.org media.prod.mdn.mozit.cloud media.stage.mdn.mozit.cloud interactive-examples.mdn.mozilla.net wikipedia.org www.google-analytics.com www.gstatic.com; manifest-src 'self'; media-src 'self' archive.org videos.cdn.mozilla.net; worker-src 'none'; report-uri https://sentry.prod.mozaws.net/api/73/security/?sentry_key=8664389dc16c4e9786e4a396f2964952;",
     'Last-Modified': 'Thu, 10 Jun 2021 02:17:05 GMT', 'Connection': 'keep-alive',
     'ETag': 'W/"589ce6d505934a796931a099bdf34668"',
     'X-Amz-Cf-Id': '_PQNmUl9zX0EBxHzKZlYV5nMdbaihLfEG3iyfoOzMroTtx-DXWAicw==',
     'Cache-Control': 'max-age=86400, public', 'Date': 'Sun, 13 Jun 2021 14:53:40 GMT', 'X-Frame-Options': 'DENY',
     'Content-Type': 'text/html; charset=utf-8',
     'Via': '1.1 e77ae8cfd42b65dd9027fa08596c6f2a.cloudfront.net (CloudFront)'}
