from urllib.parse import urlparse
import pandas as pd

# Load dataset
data = pd.read_csv("data/url_dataset.csv")

data["url"] = data["url"].str.lower().str.strip()
data["label"] = data["label"].str.lower().str.strip()


def clean_domain(u):
    parsed = urlparse(u)

    # If scheme missing, urlparse puts domain in path
    domain = parsed.netloc if parsed.netloc else parsed.path

    domain = domain.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


# Build domain -> label map
url_label_map = {
    clean_domain(url): label
    for url, label in zip(data["url"], data["label"])
}


def get_url_label(url):
    domain = clean_domain(url)
    return url_label_map.get(domain)
