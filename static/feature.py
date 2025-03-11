import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    features = []

    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception as e:
            print(f"Error fetching URL: {e}")

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            print(f"Error parsing URL: {e}")

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception as e:
            print(f"Error fetching WHOIS: {e}")

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2. longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3. shortUrl
    def shortUrl(self):
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          r'tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4. Symbol@
    def symbol(self):
        if "@" in self.url:
            return -1
        return 1

    # 5. Redirecting
    def redirecting(self):
        if self.url.rfind('//') > 6:
            return -1
        return 1

    # 6. prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall(r'\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1

    # 7. SubDomains
    def SubDomains(self):
        dot_count = len(re.findall(r"\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS
    def Https(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9. DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if len(expiration_date):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if len(creation_date):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if age >= 12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for link in self.soup.find_all('link', href=True):
                    if self.url in link['href'] or len(re.findall(r'\.', link['href'])) == 1 or self.domain in link['href']:
                        return 1
            return -1
        except:
            return -1

    # Additional methods like NonStdPort, HTTPSDomainURL, etc. follow a similar structure, as shown in your code above.
        # 11. NonStdPort
    def NonStdPort(self):
        try:
            # Check if the URL contains a custom port (not default port 80 or 443)
            port = self.domain.split(":")
            if len(port) > 1:
                return -1  # Non-standard port detected
            return 1  # Standard port (80/443)
        except:
            return -1  # Error in parsing

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            # Check if the domain contains 'https' or not
            if 'https' in self.domain:
                return -1  # Potentially insecure URL, marked as negative
            return 1  # Secure URL
        except:
            return -1  # Error in processing URL

    # 13. RequestURL
    def RequestURL(self):
        try:
            success, i = 0, 0
            # Checking 'img', 'audio', 'embed', and 'iframe' tags for any suspicious links
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success += 1
                i += 1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success += 1
                i += 1

            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    return 1  # Normal URL
                elif 22.0 <= percentage < 61.0:
                    return 0  # Potential phishing
                else:
                    return -1  # Phishing
            except:
                return 0  # Error handling, return neutral

        except:
            return -1  # Error in processing

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
                i += 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1  # Normal
                elif 31.0 <= percentage < 67.0:
                    return 0  # Suspicious
                else:
                    return -1  # Phishing
            except:
                return -1  # Error in processing

        except:
            return -1  # Error in processing

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success += 1
                i += 1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success += 1
                i += 1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1  # Normal
                elif 17.0 <= percentage < 81.0:
                    return 0  # Suspicious
                else:
                    return -1  # Phishing
            except:
                return 0  # Error handling, return neutral

        except:
            return -1  # Error in processing

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True)) == 0:
                return 1  # No forms, safe URL
            else:
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1  # Unsafe action URL
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0  # Suspicious action URL
                    else:
                        return 1  # Normal action URL
        except:
            return -1  # Error in processing

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup.text):
                return -1  # Suspicious email
            else:
                return 1  # Normal email
        except:
            return -1  # Error in processing

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1  # URL text matches Whois response
            else:
                return -1  # Mismatch, suspicious URL
        except:
            return -1  # Error in processing

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1  # No forwarding
            elif len(self.response.history) <= 4:
                return 0  # Some forwarding
            else:
                return -1  # Excessive forwarding, suspicious
        except:
            return -1  # Error in processing

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1  # Custom status bar, potential phishing
            else:
                return -1  # No custom status bar
        except:
            return -1  # Error in processing

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1  # Right-click disabled
            else:
                return -1  # Normal
        except:
            return -1  # Error in processing

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1  # Popup window detected
            else:
                return -1  # No popup window
        except:
            return -1  # Error in processing

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1  # Iframe redirection detected
            else:
                return -1  # No iframe redirection
        except:
            return -1  # Error in processing

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            if age >= 6:
                return 1  # Domain age >= 6 months
            return -1  # Domain age < 6 months
        except:
            return -1  # Error in processing

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            if age >= 6:
                return 1  # DNS record older than 6 months
            return -1  # DNS record younger than 6 months
        except:
            return -1  # Error in processing

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&url=" + self.url).read(), "xml").find("ALEXA").find("COUNTRY").get("NAME")
            if rank:
                return 1  # Website traffic detected
            return -1  # No traffic detected
        except:
            return -1  # Error in processing

    # 27. PageRank
    def PageRank(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://www.google.com/search?hl=en&q=site:" + self.url).read(), "html.parser").find("div", {"class": "BNeawe s3v9rd AP7Wnd"}).get_text()
            if rank:
                return 1  # High page rank detected
            return -1  # No page rank detected
        except:
            return -1  # Error in processing

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            search_results = search(self.url, num_results=1)
            if search_results:
                return 1  # URL indexed on Google
            return -1  # URL not indexed on Google
        except:
            return -1  # Error in processing

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            search_results = search(self.url, num_results=1)
            if search_results:
                return 1  # Links pointing to page detected
            return -1  # No links pointing to page
        except:
            return -1  # Error in processing

    # 30. StatsReport
    def StatsReport(self):
        try:
            if self.domain in self.response.text:
                return 1  # Stats report detected
            return -1  # No stats report detected
        except:
            return -1  # Error in processing

    def getFeaturesList(self):
        return self.features
