import ipaddress
import re
from urllib.parse import urlencode, urljoin, urlparse
from bs4 import BeautifulSoup
import requests
import whois
import timeit
from requests.exceptions import HTTPError, RequestException, Timeout
from datetime import datetime  # Add this line to import datetime


class FeatureExtraction1:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = None  # Initialize to None
        self.soup = None  # Initialize to None

        try:
            self.response = requests.get(url)
            self.response.raise_for_status()  # Check for HTTP errors
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
            print(
                "======================================================================================================================================================================"
            )
        except RequestException as req_ex:
            print(f"Error fetching or parsing HTML content: {req_ex}")
            print(
                "======================================================================================================================================================================"
            )

        except Exception as e:
            print(f"Unexpected error during HTML content processing: {e}")
            print(
                "======================================================================================================================================================================"
            )

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.length_url())
        self.features.append(self.length_hostname())
        self.features.append(self.ip())
        self.features.append(self.nb_dots())
        self.features.append(self.nb_qm())
        self.features.append(self.nb_eq())
        self.features.append(self.nb_slash())
        self.features.append(self.nb_www())
        self.features.append(self.ratio_digits_url())
        self.features.append(self.ratio_digits_host())
        self.features.append(self.tld_in_subdomain())
        self.features.append(self.prefix_suffix())
        self.features.append(self.shortest_word_host())
        self.features.append(self.longest_words_raw())
        self.features.append(self.longest_word_path())
        self.features.append(self.phish_hints())
        self.features.append(self.nb_hyperlinks())
        self.features.append(self.ratio_intHyperlinks())
        self.features.append(self.empty_title())
        self.features.append(self.domain_in_title())
        self.features.append(self.domain_age())
        self.features.append(self.google_index())

    # 1.length_url
    def length_url(self):
        return len(self.url)

    # 2. length_hostname
    def length_hostname(self):
        return len(urlparse(self.url).hostname)

    # 3. HaveIp
    def ip(self):
        try:
            # Extract the hostname from the URL
            hostname = urlparse(self.url).hostname

            # Check if the hostname is an IP address
            return int(ipaddress.ip_address(hostname).version == 4)
        except ValueError:
            return 0  # Not an IP address

    # 4. CountDots
    def nb_dots(self):
        return self.url.count(".")

    # 5. CountQm
    def nb_qm(self):
        return self.url.count("!")

    # 6. CountEq
    def nb_eq(self):
        return self.url.count("=")

    # 7. CountSlash
    def nb_slash(self):
        return self.url.count("/")

    # 8. CountWWW
    def nb_www(self):
        # Count the occurrences of 'www' in the URL
        return self.url.count("www")

    # 9. ratio_digits_url
    def ratio_digits_url(self):
        digits_count = sum(c.isdigit() for c in self.url)
        return digits_count / len(self.url) if len(self.url) > 0 else 0

    # 10. ratio_digits_host
    def ratio_digits_host(self):
        digits_count = sum(c.isdigit() for c in self.urlparse.hostname)
        return (
            digits_count / len(self.urlparse.hostname)
            if len(self.urlparse.hostname) > 0
            else 0
        )

    # 11. TLDinSub
    def tld_in_subdomain(self):
        tld = self.urlparse.netloc.split(".")[-1].lower()
        path = self.urlparse.path.lower()

        if path.count(tld) > 0:
            return 1
        return 0

    # 12. PrefixSufix
    def prefix_suffix(self):
        if re.findall(r"https?://[^\-]+-[^\-]+/", self.url):
            return 1
        else:
            return 0

    # 13. ShortestWord
    def shortest_word_host(self):
        try:
            hostname = urlparse(self.url).hostname
            if hostname is None:
                return 0
            # If the URL is an IP address, calculate the shortest word of the entire hostname
            if hostname.replace(".", "").isdigit():
                return min(len(part) for part in hostname.split("."))
            # Extract the subdomain (excluding the TLD and domain)
            subdomain_parts = hostname.split(".")[:-3]
            # If there are remaining parts, join them to get the subdomain
            if subdomain_parts:
                subdomain = ".".join(subdomain_parts)
            else:
                return 0
            # Split the subdomain into words
            words_raw = subdomain.split(".")
            if len(words_raw) == 0:
                return 0
            return min(len(word) for word in words_raw)
        except:
            return 0

    # 14. longest_words_raw
    def longest_words_raw(self):
        try:
            url_parts = urlparse(self.url)

            # Combine all relevant parts of the URL into a single string
            url_string = ".".join(
                filter(
                    None,
                    [
                        url_parts.netloc,
                        url_parts.path,
                        url_parts.params,
                        url_parts.query,
                    ],
                )
            )

            # Remove slashes from the URL string
            url_string = url_string.replace("/", ".")
            url_string1 = url_string.replace("-", ".")

            if url_string:
                # Find the longest word in the modified URL string
                words_raw = url_string1.split(".")
                return max(len(word) for word in words_raw)
            else:
                return 0
        except:
            return 0

    # 15. LongestWordPath
    def longest_word_path(self):
        try:
            url_parts = urlparse(self.url)

            # Extract the path (excluding the slashes)
            path_string = url_parts.path.replace("/", ".")
            path_string1 = path_string.replace("-", ".")

            if path_string:
                # Find the longest word in the path string
                words_raw = path_string1.split(".")
                return max(len(word) for word in words_raw)
            else:
                return 0
        except:
            return 0

    # 16. phish_hints
    def phish_hints(self):
        count = 0
        HINTS = [
            "wp",
            "login",
            "includes",
            "admin",
            "content",
            "site",
            "images",
            "js",
            "alibaba",
            "css",
            "myaccount",
            "dropbox",
            "themes",
            "plugins",
            "signin",
            "view",
            "secure",
            "account",
            "verification",
            "update",
            "paypal",
            "bank",
            "login",
            "password",
            "confirm",
            "billing",
            "service",
            "support",
        ]

        # Convert the URL path to lowercase for case-insensitive matching
        url_path_lower = self.url.lower()

        for hint in HINTS:
            count += url_path_lower.count(hint)

        return count

    def nb_hyperlinks(self):
        try:
            if self.soup is not None:
                href_links = len(self.soup.find_all("a", href=True))
                link_links = len(self.soup.find_all("link", href=True))
                media_links = len(self.soup.find_all("[src]"))
                form_links = len(self.soup.find_all("form"))
                css_links = len(self.soup.find_all("style"))
                favicon_links = len(self.soup.find_all("link", rel="icon"))

                return (
                    href_links
                    + link_links
                    + media_links
                    + form_links
                    + css_links
                    + favicon_links
                )
            else:
                print("Error: Soup is not properly initialized.")
                return 0
        except Exception as e:
            print(f"Error in nb_hyperlinks: {e}")
            return 0

    def ratio_intHyperlinks(self):
        if self.soup is not None:
            internal_links = []

            # Href (same condition as in h_internal)
            internal_links += [
                a["href"]
                for a in self.soup.find_all("a", href=True)
                if not urljoin(self.url, a["href"]).startswith(urljoin(self.url, "/"))
            ]
            # Link
            internal_links += [
                link["href"]
                for link in self.soup.find_all("link", href=True)
                if not urljoin(self.url, link["href"]).startswith(("http", "www"))
            ]
            # Media
            internal_links += [
                media["src"]
                for media in self.soup.find_all("[src]")
                if not urljoin(self.url, media["src"]).startswith(("http", "www"))
            ]
            # Form
            internal_links += [
                form["action"]
                for form in self.soup.find_all("form", action=True)
                if not urljoin(self.url, form["action"]).startswith(("http", "www"))
            ]
            # CSS
            internal_links += [css.text for css in self.soup.find_all("style")]
            # Favicon
            internal_links += [
                favicon["href"]
                for favicon in self.soup.find_all("link", rel="icon")
                if not urljoin(self.url, favicon["href"]).startswith(("http", "www"))
            ]

            total_links = self.nb_hyperlinks()
            internal_links_count = len(internal_links)

            if total_links == 0:
                return 0
            else:
                return internal_links_count / total_links
        else:
            return 0

    # 18. EmptyTitle
    def empty_title(self):
        try:
            if self.soup and self.soup.title:
                return int(not bool(self.soup.title.text.strip()))
            return 0
        except Exception as e:
            print(f"Error checking empty title: {e}")
            return 0

    # 19. domain_in_title
    def domain_in_title(self):
        try:
            if self.soup and self.soup.title:
                domain = urlparse(self.url).netloc
                title_text = self.soup.title.text
                return 0 if domain.lower() in title_text.lower() else 1
            return 0  # Default to 0 when title is not present
        except Exception as e:
            print(f"Error checking domain in title: {e}")
            return 0

    # 20. domain_age
    def domain_age(self):
        try:
            creation_dates = self.whois_response.creation_date

            if creation_dates:
                if isinstance(creation_dates, list):
                    # Choose the first creation date if there are multiple dates
                    creation_date = creation_dates[0]
                else:
                    creation_date = creation_dates

                today = datetime.now()
                age = (today - creation_date).days
                return age
            else:
                return -1
        except Exception as e:
            print(f"Error calculating domain age: {e}")
            return -1

    # 21. google_index
    def google_index(self):
        user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36"
        headers = {"User-Agent": user_agent}
        query = {"q": "site:" + self.url}
        google = "https://www.google.com/search?" + urlencode(query)

        try:
            # Introduce a timeout for the requests.get operation
            data = requests.get(google, headers=headers, timeout=5)
            data.encoding = "ISO-8859-1"
            soup = BeautifulSoup(str(data.content), "html.parser")

            if (
                "Our systems have detected unusual traffic from your computer network."
                in str(soup)
            ):
                return -1

            check = soup.find(id="rso").find("div").find("div").find("a")

            if check and check["href"]:
                return 0
            else:
                return 1
        except (requests.Timeout, AttributeError):
            return 1
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0

    def getFeaturesList(self):
        return self.features
