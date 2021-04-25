# Purpose - This file is run to extract all the features from a webpage to determine
# whether it is a phishing or legitimate site
# Notes - 
# 1 stands for Legitimate
# 0 stands for Suspicious
# -1 stands for Phishing

from os import stat
from bs4 import BeautifulSoup
import urllib.request
import bs4
import re
import socket
import whois
from datetime import datetime, time
import time
import config

from googlesearch import search

# This import is needed only when you run this file in isolation
import sys

from patterns import *

# Store Path Variables Here. It is OS Dependent
LOCALHOST_PATH = config.LOCALHOST_PATH
DIRECTORY_NAME = config.DIRECTORY_NAME

def isIPInUrl(url):
    ip_pattern = ipv4_pattern + "|" + ipv6_pattern
    check_match = re.search(ip_pattern, url)
    return -1 if check_match else 1

def isLongURL(url):
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return -1

def isTinyURL(url):
    check_match = re.search(shortening_services, url)
    return -1 if check_match else 1

def isAlphaNumericURL(url):
    check_match = re.search('@', url)
    return -1 if check_match else 1

def isRedirectingURL(url):
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1

def isHyphenatedPrefixSuffix(domain):
    check_match = re.search('-', domain)
    return -1 if check_match else 1

def isSubdomainMultiDomain(url):
    if isIPInUrl(url) == -1:
        check_match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        positioning = check_match.end()
        url = url[positioning:]
    dots_number = [x.start() for x in re.finditer(r'\.', url)]
    if len(dots_number) <= 3:
        return 1
    elif len(dots_number) == 4:
        return 0
    else:
        return -1

def isRecentlyRegisteredDomain(domain):
    expiration_date = domain.expiration_date
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')

    registration_length = 0

    # Determine if domain has expiration date or not. Use expiration dat only when present
    if expiration_date:
        registration_length = abs((expiration_date - today).days)
    return -1 if registration_length / 365 <= 1 else 1

def isFaviconSameDomain(wiki, soup, domain):
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', head.link['href'])]
            return 1 if wiki in head.link['href'] or len(dots) == 1 or domain in head.link['href'] else -1
    return 1

def isHttpTokenInDomainURL(url):
    check_match = re.search(http_https, url)
    if check_match and check_match.start() == 0:
        url = url[check_match.end():]
    check_match = re.search('http|https', url)
    return -1 if check_match else 1

def isRequestURLValid(wiki, soup, domain):
    i = 0
    success = 0
    for img in soup.find_all('img', src=True):
        dots = [x.start() for x in re.finditer(r'\.', img['src'])]
        if wiki in img['src'] or domain in img['src'] or len(dots) == 1:
            success += 1
        i += 1
    
    for audio in soup.find_all('audio', src=True):
        dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
        if wiki in audio['src'] or domain in audio['src'] or len(dots) == 1:
            success += 1
        i += 1
    
    for embed in soup.find_all('embed', src=True):
        dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
        if wiki in embed['src'] or domain in embed['src'] or len(dots) == 1:
            success += 1
        i += 1
    
    for i_frame in soup.find_all('i_frame', src=True):
        dots = [x.start() for x in re.finditer(r'\.', i_frame['src'])]
        if wiki in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1:
            success += 1
        i += 1
    
    try:
        percentage = success / float(i) * 100
    except:
        return 1
    
    if percentage < 22.0:
        return 1
    elif 22.0 <= percentage < 61.0:
        return 0
    else:
        return -1

def isURLAnchorValid(wiki, soup, domain):
    i = 0
    unsafe = 0
    for a in soup.find_all('a', href=True):
        # 2nd condition was 'JavaScript :: void(0)' but we put JavaScript because the space between JavaScript and ::
        # might not be there in the actul a['href']
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not ( wiki in a['href'] or domain in a['href']):
            unsafe += 1
        i += 1
        # print(a['href'])

    try:
        percentage = unsafe / float(i) * 100
    except:
        return 1
    
    if percentage < 31.0:
        return 1
    elif 31.0 <= percentage < 67.0:
        return 0
    else:
        return -1

# Determine Links in <meta> tag, <script> tag and <link) tag
def isLinkInTags(wiki, soup, domain):
    i = 0
    success = 0
    for link in soup.find_all('link', href=True):
        dots = [x.start() for x in re.finditer(r'\.', link['href'])]
        if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
            success += 1
        i += 1
    
    for script in soup.find_all('script', src=True):
        dots = [x.start() for x in re.finditer(r'\.', script['src'])]
        if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
            success += 1
        i += 1
    
    try:
        percentage = success / float(i) * 100
    except:
        return 1
    
    if percentage < 17.0:
        return 1
    elif 17.0 <= percentage < 81.0:
        return 0
    else:
        return -1

# Server Form Handler (SFH)
def isSFH(wiki, soup, domain):
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            return -1
        elif wiki not in form['action'] and domain  not in form['action']:
            return 0
        else:
            return 1
    return 1

# PHP Mail Function determiner
def isPHPMailable(soup):
    for form in soup.find_all('form', action=True):
        return -1 if "mailto:" in form['action'] else 1
    
    # Safe to return 1 if no form in the soup data
    return 1

def isAbnormalURL(domain, url):
    hostname = domain.name
    check_match = re.search(hostname, url)
    return 1 if check_match else -1

# Handles iFrame Redirection
def i_frame(soup):
    for i_frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
        # Even if one iFrame satisfies these below conditions the it is safe to say it is a phishing site
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameBorder'] == "0":
            return -1
        if i_frame['width'] == "0" or i_frame['height'] == "0" or i_frame['frameBorder'] == "0":
            return 0
        
    # If none has width, height or frameBorder then return 1
    return 1

def isDomainOld(domain):
    creation_date = domain.creation_date
    expiration_date = domain.expiration_date
    ageOfDomain = 0
    if expiration_date:
        ageOfDomain = abs((expiration_date - creation_date).days)
    return -1 if ageOfDomain / 30 < 6 else 1

def isWebTraffic(url):
    try:
        rank = \
            bs4.BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
    except TypeError:
        return -1
    
    rank = int(rank)
    return 1 if rank < 100000 else 0

def isGoogleIndex(url):
    site = search(url, 5)
    return 1 if site else -1

def isStatisticalReport(url, hostname):
    try:
        ipAddress = socket.gethostbyname(hostname)
    except:
        return -1
    
    urlMatch = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ipMatch = re.search(
        '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
        ipAddress)
    
    if urlMatch:
        return -1
    elif ipMatch:
        return -1
    else:
        return 1

def getHostnameFromURL(url):
    hostname = url
    pre_pattern_match = re.search(get_hostname_pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]
    return hostname



def main(url):
    with open(LOCALHOST_PATH + DIRECTORY_NAME + '/markup.txt', 'r', encoding='utf-8') as file:
        soup_string = file.read()
    
    soup = BeautifulSoup(soup_string, 'html.parser')

    status = []
    hostname = getHostnameFromURL(url)

    status.append(isIPInUrl(url))
    status.append(isLongURL(url))
    status.append(isTinyURL(url))
    status.append(isAlphaNumericURL(url))
    status.append(isRedirectingURL(url))
    status.append(isHyphenatedPrefixSuffix(url))
    status.append(isSubdomainMultiDomain(url))  

    dns = 1
    try:
        domain = whois.query(hostname)
    except:
        dns = -1
    
    status.append(-1 if dns == -1 else isRecentlyRegisteredDomain(domain))
    status.append(isFaviconSameDomain(url, soup, hostname))
    status.append(isHttpTokenInDomainURL(url))
    status.append(isRequestURLValid(url, soup, hostname))
    status.append(isURLAnchorValid(url, soup, hostname))
    status.append(isLinkInTags(url, soup, hostname))
    status.append(isSFH(url, soup, hostname))
    status.append(isPHPMailable(soup))

    status.append(-1 if dns == -1 else isAbnormalURL(domain, url))

    status.append(i_frame(soup))

    status.append(dns)

    status.append(isWebTraffic(soup))
    status.append(isGoogleIndex(url))
    status.append(isStatisticalReport(url, hostname))

    # print('\n1. Having IP address\n2. URL Length\n3. URL Shortening service\n4. Having @ symbol\n'
    #       '5. Having double slash\n6. Having dash symbol(Prefix Suffix)\n7. Having multiple subdomains\n'
    #       '8. Domain Registration Length\n9. Favicon\n10. HTTP or HTTPS token in domain name\n'
    #       '11. Request URL\n12. URL of Anchor\n13. Links in tags\n14. SFH\n15. Submitting to email\n16. Abnormal URL\n'
    #       '17. IFrame\n18. Age of Domain\n19. DNS Record\n20. Web Traffic\n21. Google Index\n22. Statistical Reports\n')
    # print(status)
    return status


# # Use the below two lines if features_extraction.py is being run as a standalone file. If you are running this file as
# # a part of the workflow pipeline starting with the chrome extension, comment out these two lines.
# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Please use the following format for the command - `python features_extraction.py <url-to-be-tested>`")
#         exit(0)
#     main(sys.argv[1])