CSV="findings.csv"
python3 - <<'PY'
import csv, sys, re
from pathlib import Path
CSV=Path("findings.csv")
if not CSV.exists():
    print("CSV file not found:", CSV); sys.exit(1)

rows=[]
with CSV.open(newline='', encoding='utf-8', errors='replace') as fh:
    reader=csv.DictReader(fh)
    cols=reader.fieldnames
    print("Detected columns:", cols)
    # heuristics for columns
    def pick(names):
        names=[n.lower() for n in names]
        for cand in names:
            for c in cols:
                if cand in c.lower():
                    return c
        return None
    host_col = pick(['host','hostname','host ip'])
    port_col = pick(['port','port/proto','port/protocol'])
    vuln_col = pick(['name','nvt','vulnerability','vuln','title'])
    cvss_col = pick(['cvss','score'])
    cve_col  = pick(['cve','reference','references','refs'])
    # fallback
    if not vuln_col:
        vuln_col = cols[0]
    if not host_col:
        host_col = cols[1] if len(cols)>1 else cols[0]

    for r in reader:
        host = r.get(host_col,'').strip() if host_col else ''
        port = r.get(port_col,'').strip() if port_col else ''
        vuln = r.get(vuln_col,'').strip() if vuln_col else ''
        cvss = r.get(cvss_col,'').strip() if cvss_col else ''
        cve  = r.get(cve_col,'').strip() if cve_col else ''
        # normalize CVSS to float when possible
        try:
            cvss_f = float(re.findall(r'([0-9]+(?:\.[0-9]+)?)', cvss)[0]) if cvss else None
        except:
            cvss_f = None
        # extract first CVE if multiple
        m = re.search(r'(CVE-\d{4}-\d{4,7})', cve, re.IGNORECASE)
        cve_first = m.group(1).upper() if m else ''
        rows.append({'Host':host,'Port':port,'Vulnerability':vuln,'CVSS':cvss_f if cvss_f is not None else '', 'CVE':cve_first})
# sort by CVSS desc
rows_sorted = sorted(rows, key=lambda x: (x['CVSS'] if x['CVSS']!='' else -1), reverse=True)
out = Path('findings_summary.csv')
with out.open('w', newline='', encoding='utf-8') as ofh:
    writer = csv.DictWriter(ofh, fieldnames=['Host','Port','Vulnerability','CVSS','CVE'])
    writer.writeheader()
    for r in rows_sorted:
        writer.writerow(r)
print(f"Wrote {out} ({len(rows_sorted)} rows). Top 30 entries:")
# pretty print top 30
from itertools import islice
print("{:20} {:7} {:6} {}".format("Host","Port","CVSS","CVE"))
for r in islice(rows_sorted, 30):
    cv = r['CVSS'] if r['CVSS']!='' else ''
    print(f"{r['Host'][:20]:20} {r['Port'][:7]:7} {str(cv):6} {r['CVE']}")
PY
