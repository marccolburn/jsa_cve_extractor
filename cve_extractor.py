import requests,re,csv
from bs4 import BeautifulSoup
from tqdm import tqdm

def get_html_page(url):
    """Get HTML Page and return"""
    r = requests.get(url)
    return r.text

def parse_juniper_page(html_page):
    """Read HTML and return CVE if it exists"""
    soup = BeautifulSoup(html_page, 'html.parser')
    all_divs = soup.find_all('div')
    cve_list = []
    cve_counter = 0
    for div in all_divs:
        cve_data = re.search('CVE-\d{4}-\d{4}', div.text)
        if cve_data != None:
            cve_text = cve_data.group(0)
            if cve_text not in cve_list:
                cve_list.append(cve_text)
                cve_counter += 1
    return cve_list,cve_counter

def parse_nist_page(html_page):
    """Read HTML and return CVSS Score"""
    soup = BeautifulSoup(html_page, 'html.parser')
    #all_divs = soup.find_all('div')
    base_score_raw = soup.find('span', class_="severityDetail")
    base_score_text = base_score_raw.find('a')
    cvss_score = base_score_text.string
    return cvss_score

def dump_to_csv(cve_dict):
    "Dump Dictionary contents to CSV"""
    with open("cve_data.csv", "w") as csv_file:
        csv_writer = csv.writer(csv_file, delimiter=",")
        csv_writer.writerow(['JSA', 'CVE', 'CVSS Score', 'CVSS Category'])
        for jsa, cves in cve_dict.items():
            cvss_numbers = []
            cvss_categories = []
            for cvss in cves['cvss_scores']:
                try:
                    cvss_number, cvss_category = cvss.split(' ')
                except ValueError:
                    cvss_number = '0'
                    cvss_category = 'None'
                cvss_numbers.append(cvss_number)
                cvss_categories.append(cvss_category)
            print(cvss_numbers, cvss_categories)
            csv_writer.writerow([jsa,' '.join(cves['cves']),' '.join(cvss_numbers),' '.join(cvss_categories)])


if __name__ == "__main__":
    with open('jseries_list_of_jsas.txt') as jsa_list:
        jsa_read = jsa_list.readlines()
        cve_dict = {}
        for line in tqdm(jsa_read):
            url = "https://kb.juniper.net/InfoCenter/index?page=content&id={0}&cat=J_SERIES&actp=LIST".format(line.strip())
            html_page = get_html_page(url)
            cve_list, cve_counter = parse_juniper_page(html_page)
            cve_dict[line.strip()] = {}
            cve_dict[line.strip()]['cves'] = cve_list
    for jsa, cves in tqdm(cve_dict.items()):
        if cves != None:
            cvss_scores = []
            for cve in cves['cves']:
                url="https://nvd.nist.gov/vuln/detail/{0}".format(cve)
                html_page = get_html_page(url)
                try:
                    cvss_score = parse_nist_page(html_page)
                    cvss_scores.append(cvss_score)
                except AttributeError:
                    cvss_scores.append('error')
            cve_dict[jsa]['cvss_scores'] = cvss_scores
    dump_to_csv(cve_dict)
    #print(cve_dict)
    print(cve_counter)
            
