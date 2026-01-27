import requests 
import json
import re
import pandas as pd
import tabulate

def printBanner():
    print(r"""
       .-''''-.
     .'        '.
    /            \
   |,  .-.  .-.  ,|
   | )(_o/  \o_)( |
   |/     /\     \|
   (_     ^^     _)
    \__|IIIIII|__/
     | \IIIIII/ |
     \          /
      `--------`

            CVEye — All-Seeing CVE Intelligence
    """)



COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[91m",  # red
    "MEDIUM":   "\033[93m",  # orange / yellow
    "LOW":      "\033[33m",  # yellow
    "RESET":    "\033[0m" # reset color
}

def colorize(severity, text):
    return f"{COLORS.get(severity, '')}{text}{COLORS['RESET']}"

def getCVEInformation(cveJson):
    description = cveJson["descriptions"][0]["value"]
    vectorString = cveJson["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"]
    

    baseScore = float(cveJson["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"])
    if baseScore >= 0.1 and  baseScore <= 3.9:
        scolor = COLORS['LOW']
    elif baseScore >= 4.0  and  baseScore <= 6.9:
        scolor = COLORS['MEDIUM']
    elif baseScore >= 7.0  and  baseScore <= 8.9:
        scolor = COLORS['HIGH']
    else:
        scolor = COLORS['CRITICAL']

    baseSeverity = cveJson["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
    

    try:
        weaknesses = cveJson.get("weaknesses", [])
    except (KeyError, IndexError, TypeError):
        return []
    
    cwes = []

    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
               value = desc.get("value")
            if value and value.startswith("CWE-"):
                cwes.append(value)


    return [
        description,
        vectorString,
        baseScore,
        baseSeverity,
        cwes,
        scolor
    ]


def printMenu():
    print("=" * 80)
    printBanner()
    print("=" * 80)
    print()
    print("Please select an option:")
    print()
    print(" [1] Search by CVE ID")
    print(" [2] Search by Description")
    print(" [3] Show CVE Summary")
    print(" [0] Exit")
    print()
    print("="*50)

def printSummary(summary):
    print("=" * 80)
    print(f"Vulnerability : {summary[0]}")
    print(f"Product       : {summary[2]}")
    print(f"Vendor        : {summary[1]}")
    print(f"Links         : {summary[3]}")
    print("=" * 80)


printMenu()
choice = int(input("Enter Your Choice: "))

if(choice == 1):
    cveID = input("Enter CVE ID or Description: (CVE-XXXX-XXXX) ").upper()
    regex = "CVE-([0-9]+)-([0-9]+)"

    if not (re.search(regex, cveID)):
        print("Error! Please Enter valid CVE format")
        exit()


    cve = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveID}")
    # print(json.dumps(cve.json(), indent=4))

    cveJson = cve.json()["vulnerabilities"][0]["cve"]

    # print()
    # print("Description: ")
    # print(getCVEInformation(cveJson)[0])
    # print()

    # print(f"Vector String: {getCVEInformation(cveJson)[1]}")
    # print()

    severity = getCVEInformation(cveJson)[5]
    formatedBaseScore = f"{severity}{getCVEInformation(cveJson)[2]} ({getCVEInformation(cveJson)[3]}){COLORS['RESET']}"

    # get cwe data
    cwe = requests.get('https://docs.opencve.io/v1/api/cwe/')

    # load the cisa csv for data searching
    # downloaded from https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    # kve dataset downloaded to https://zenodo.org/records/16747173

    cisa = pd.read_csv("datasets/known_exploited_vulnerabilities.csv", )
    kve = pd.read_csv("datasets/kev-02.13.2025_attack-15.1-enterprise.csv")

    # format to Upper case and strip unwanted characters
    cisa['cveID'] = cisa['cveID'].str.upper().str.strip()
    kve['capability_id'] = kve['capability_id'].str.upper().str.strip()

    # merge first df with the second df
    # this is same as joins in sql
    merged = pd.merge(
        cisa,
        kve,
        left_on="cveID",
        right_on="capability_id",
        how="left",  # keep all CISA CVEs, even if Zenodo has no match
        suffixes=("_cisa", "_attack")
    )

    # getting all strings in the df
    mergedObj  = merged.select_dtypes(include='str') 
    # only replace str with N/A 
    merged[mergedObj.columns] = mergedObj.fillna("N/A")

    # get the row with the cveID
    row = merged.loc[merged['cveID'] == cveID]
    
    attackTechnique = ''
    if not row.empty:
        # iterate over the rows 
        for idx, row in row.iterrows():
            formatedTxt = f"{row['attack_object_id']} - {row['attack_object_name']}"
            attackTechnique += ''.join(formatedTxt) + "\n"

            cisaURLs = re.findall(r'https?://\S+', row['notes'])
            kveURLs = re.findall(r'https?://\S+', row['references'])

        formatedUrl = ", ".join(cisaURLs + kveURLs).strip('\']')

        # title = row['vulnerabilityName']
        # vendor = row['vendorProject']
        # product = row['product'] 

        summary = [row['vulnerabilityName'], row['vendorProject'], row['product'], formatedUrl]
        printSummary(summary)

    
    # now construct a new object with all the data

    info = getCVEInformation(cveJson)
    table = [{
        "CVE ID":cveID,
       # "CWE": ''.join(str(cwe) for cwe in info[4]),
        "Description": info[0][:20] + "..." if len(info[0]) > 20 else info[0],
        "Vector String": info[1],
        "Base Score": formatedBaseScore,
        "Att&ck Techniques": attackTechnique
    }]

   
    
    print()
    print(tabulate.tabulate(table, headers="keys", tablefmt="grid"))



