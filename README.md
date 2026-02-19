# VintHub #
VintHub is a lightweight, python library and CLI tool designed to analyze Common Vulnerabilities and Exposures (CVEs). It replicates the exact logic used in https://vinthub.pages.dev, providing detailed insights into vulnerability metrics, PoCs, and SSVC decisions.

Full features description available at: https://vinthub.pages.dev/about

### Dependencies installation
```
pip install -r requirements.txt
```

### Usage - Command Line Interface (CLI)
Analyze one or more CVEs directly from your terminal. Inputs can be space-separated or comma-separated.

Analysis with JSON output to terminal:
```
python vinthub.py CVE-2023-23397 CVE-2021-44228
```

Analysis with CSV export:
```
python vinthub.py CVE-2023-23397,CVE-2021-44228 -o report.csv
```

Analysis with JSON export:
```
python vinthub.py CVE-2023-23397 -o report.json
```

### Usage - Python Library
```
from vinthub import VintHub

vh = VintHub()

# Single Analysis
result = vh.analyze("CVE-2023-23397")
print(f"Published: {result['Published']}, Score: {result['Score']}")

# Batch analysis
cve_list = ["CVE-2023-23397", "CVE-2021-44228"]
results = vh.batch_analyze(cve_list, show_progress=True)
print(results)
```
