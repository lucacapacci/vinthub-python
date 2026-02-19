import requests
import re
import json
import csv
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

class VintHub:
    def __init__(self):
        self.base_nvd = "https://lucacapacci.github.io/nvd/cve/{year}/{cve}.json"
        self.base_epss = "https://lucacapacci.github.io/epss/data_single/{year}/{cve}.csv"
        self.base_kev = "https://lucacapacci.github.io/cisa_kev/data_single/{year}/{cve}.csv"
        self.base_poc = "https://raw.githubusercontent.com/lucacapacci/PoC-in-GitHub/refs/heads/main/{year}/{cve}.json"
        self.base_edb = "https://lucacapacci.github.io/exploitdb/data_single/{year}/{cve}.csv"
        self.base_cve_proj = "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/{year}/{prefix}/{cve}.json"

    def _capitalize(self, s):
        if not s: return ""
        return " ".join(w.capitalize() for w in re.split(r'[\s_-]+', s))

    def _get_ssvc_decision(self, vector):
        mapping = {
            "E:N/A:N/T:P": ("TRACK", "Standard update timeline"),
            "E:N/A:N/T:T": ("TRACK*", "Monitor closely"),
            "E:N/A:Y/T:P": ("ATTEND", "Attention required"),
            "E:N/A:Y/T:T": ("ATTEND", "Attention required"),
            "E:P/A:N/T:P": ("TRACK*", "Monitor closely"),
            "E:P/A:N/T:T": ("ATTEND", "Attention required"),
            "E:P/A:Y/T:P": ("ATTEND", "Attention required"),
            "E:P/A:Y/T:T": ("ATTEND", "Attention required"),
            "E:A/A:N/T:P": ("ATTEND", "Attention required"),
            "E:A/A:N/T:T": ("ACT", "Immediate action"),
            "E:A/A:Y/T:P": ("ACT", "Immediate action"),
            "E:A/A:Y/T:T": ("ACT", "Immediate action")
        }
        pure_vec = "/".join(vector.split('/')[1:])
        return mapping.get(pure_vec, ("UNKNOWN", "N/A"))

    def analyze(self, cve_id):
        cve_id = cve_id.upper().strip()
        year = cve_id.split('-')[1]
        id_num = cve_id.split('-')[2]
        prefix = f"{id_num[:-3]}xxx" if len(id_num) > 3 else "0xxx"

        try:
            nvd_req = requests.get(self.base_nvd.format(year=year, cve=cve_id))
            if not nvd_req.ok: return {"VULN ID": cve_id, "error": "Not Found"}
            cve_data = nvd_req.json().get('cve', {})

            epss_res = requests.get(self.base_epss.format(year=year, cve=cve_id)).text if requests.get(self.base_epss.format(year=year, cve=cve_id)).ok else ""
            kev_res = requests.get(self.base_kev.format(year=year, cve=cve_id)).text if requests.get(self.base_kev.format(year=year, cve=cve_id)).ok else ""
            poc_git = requests.get(self.base_poc.format(year=year, cve=cve_id)).json() if requests.get(self.base_poc.format(year=year, cve=cve_id)).ok else []
            edb_res = requests.get(self.base_edb.format(year=year, cve=cve_id)).text if requests.get(self.base_edb.format(year=year, cve=cve_id)).ok else ""
            proj = requests.get(self.base_cve_proj.format(year=year, prefix=prefix, cve=cve_id)).json() if requests.get(self.base_cve_proj.format(year=year, prefix=prefix, cve=cve_id)).ok else {}

            products = set()
            for node in cve_data.get('configurations', []):
                for n in node.get('nodes', []):
                    for m in n.get('cpeMatch', []):
                        parts = m['criteria'].split(':')
                        if len(parts) >= 5:
                            v, p = parts[3].replace('\\', '').replace('_', ' '), parts[4].replace('\\', '').replace('_', ' ')
                            products.add(f"{self._capitalize(v)} {self._capitalize(p)}".strip())
            
            if not products and proj:
                affected_list = proj.get('containers', {}).get('cna', {}).get('affected', [])
                for a in affected_list:
                    v, p = a.get('vendor', ''), a.get('product', '')
                    if v or p: products.add(f"{v} {p}".strip())

            poc_links = [p['html_url'] for p in poc_git]
            if edb_res and '\n' in edb_res:
                lines = edb_res.splitlines()
                if len(lines) > 1:
                    edb_id = lines[1].split(',')[0]
                    poc_links.append(f"https://www.exploit-db.com/exploits/{edb_id}")
            for ref in cve_data.get('references', []):
                if "Exploit" in ref.get('tags', []):
                    ref['url'] = re.sub(r'^http://', 'https://', ref['url'])
                    if "securityfocus.com/bid/" in ref['url']:
                        ref['url'] = f"https://web.archive.org/web/2018/{ref['url']}"
                    poc_links.append(ref['url'])
            poc_links = list(set(poc_links))

            epss_val = "N/A"
            if epss_res:
                for line in epss_res.splitlines():
                    if line.startswith(cve_id):
                        parts = line.split(',')
                        if len(parts) > 1:
                            epss_val = f"{float(parts[1])*100:.3f}%"
                        break

            # FIXED KEV LOGIC: Check row by row for CVE ID and return dateAdded or "No"
            kev_val = "No"
            ransomware = "No"
            if kev_res:
                reader = csv.DictReader(kev_res.strip().splitlines())
                for row in reader:
                    if row.get('cveID') == cve_id:
                        kev_val = row.get('dateAdded', "Yes")
                        if row.get('knownRansomwareCampaignUse') == "Known":
                            ransomware = "Yes"
                        break

            exploitation = "A" if kev_val != "No" else ("P" if poc_links else "N")
            
            metrics = cve_data.get('metrics', {})
            metric_list = metrics.get('cvssMetricV40') or metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30') or metrics.get('cvssMetricV2') or []
            best = metric_list[0] if metric_list else {}
            cvss = best.get('cvssData', {})
            
            severity = (best.get('baseSeverity') or cvss.get('baseSeverity') or "N/A").upper()
            score = cvss.get('baseScore', 0.0)

            av = cvss.get('attackVector', cvss.get('accessVector', '')).upper()
            pr = cvss.get('privilegesRequired', cvss.get('authentication', '')).upper()
            ui = cvss.get('userInteraction', '').upper()
            ac = cvss.get('attackComplexity', cvss.get('accessComplexity', '')).upper()
            
            aut = "Y" if (av == "NETWORK" and pr in ["NONE", "N"] and ui in ["NONE", ""] and ac == "LOW") else "N"
            ti = "T" if (cvss.get('confidentialityImpact') in ["HIGH", "COMPLETE"] and cvss.get('integrityImpact') in ["HIGH", "COMPLETE"]) else "P"
            
            ssvc_vec = f"CISA:2.0.3/E:{exploitation}/A:{aut}/T:{ti}"
            ssvc_dec, ssvc_label = self._get_ssvc_decision(ssvc_vec)

            links = [f"https://nvd.nist.gov/vuln/detail/{cve_id}", f"https://www.cve.org/CVERecord?id={cve_id}"]
            if kev_val != "No": links.append(f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}")

            return {
                "VULN ID": cve_id,
                "Published": cve_data.get('published', '').split('T')[0],
                "Product": sorted(list(products)),
                "Score": score,
                "Severity": severity,
                "Vector": cvss.get('vectorString', "N/A"),
                "SSVC Decision": f"{ssvc_dec}",
                "SSVC Vector": ssvc_vec,
                "EPSS": epss_val,
                "KEV": kev_val,
                "Ransomware": ransomware,
                "PoCs": sorted(poc_links),
                "CWE": list(set(re.findall(r'CWE-\d+', json.dumps(proj or nvd_req.json())))),
                "CAPEC": list(set(re.findall(r'CAPEC-\d+', json.dumps(proj or nvd_req.json())))),
                "Links": links
            }
        except Exception as e:
            return {"VULN ID": cve_id, "error": str(e)}

    def batch_analyze(self, cve_list, show_progress=False, max_workers=10):
        results = [None] * len(cve_list)
        cve_to_idx = {cve: i for i, cve in enumerate(cve_list)}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_cve = {executor.submit(self.analyze, cve): cve for cve in cve_list}
            completed_count = 0
            for future in as_completed(future_to_cve):
                cve = future_to_cve[future]
                idx = cve_to_idx[cve]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {"VULN ID": cve, "error": str(e)}
                completed_count += 1
                if show_progress:
                    sys.stderr.write(f"\rProgress: {completed_count}/{len(cve_list)}")
                    sys.stderr.flush()
        if show_progress: sys.stderr.write("\n")
        return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cves", nargs="+")
    parser.add_argument("-o", "--output")
    parser.add_argument("-w", "--workers", type=int, default=10)
    args = parser.parse_args()

    input_list = []
    for item in args.cves:
        input_list.extend(item.replace(',', ' ').split())
    
    vh = VintHub()
    results = vh.batch_analyze(input_list, show_progress=True, max_workers=args.workers)

    if args.output:
        if args.output.endswith('.csv'):
            with open(args.output, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        elif args.output.endswith('.json'):
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
        else:
            print("ERROR: unkown output format")
            exit()
    else:
        print(json.dumps(results, indent=2))
