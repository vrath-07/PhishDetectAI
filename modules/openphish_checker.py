import requests

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

def fetch_openphish_feed():
    try:
        response = requests.get(OPENPHISH_FEED_URL, timeout=10)
        response.raise_for_status()
        return set(response.text.strip().split('\n'))
    except Exception as e:
        print(f"[!] Failed to fetch OpenPhish feed: {e}")
        return set()

def is_url_in_openphish(url, openphish_set):
    return url in openphish_set
