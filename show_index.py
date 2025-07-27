import requests

DEFAULT_INDEX_URL = "https://pypi.org/simple/"

def fetch_index():
    response = requests.get(DEFAULT_INDEX_URL)
    response.raise_for_status()
    for l in response.text.split("\n"):
        if l.startswith('<a href="/simple/'):
            pkgname = l.split("/")[2]
            yield pkgname

def main():
    for pkg in fetch_index():
        print(pkg)

if __name__ == "__main__":
    main()
