# Tiny app used as testing target

Tiny sample application used for testing the main system. It provides two small utilities:

- DNS lookups (`A`, `AAAA`, `MX`) using `dnspython`.
- Querying crt.sh for certificate transparency entries (JSON).

Usage examples:

```
python app.py dns example.com
python app.py crt example.com
python app.py all example.com
```

### Example:


```
$ python app.py all python.org
{
  "domain": "python.org",
  "dns": {
    "A": [
      "151.101.192.223",
      "151.101.64.223",
      "151.101.128.223",
      "151.101.0.223"
    ],
    "AAAA": [],
    "MX": [
      {
        "preference": 50,
        "exchange": "mail.python.org"
      }
    ]
  },
  "crt": []
}
```


Install dependencies:

```
pip install -r requirements.txt
```

This app is intentionally small and dependency-light so it can be used in integration tests.
