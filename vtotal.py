import requests
import sqlite3
import pandas as pd


class VtScan(object):

    db = sqlite3.connect("pyscan")
    cur = db.cursor()
    api_key = ''
    auto_run = True

    # VT Scan URLs
    scan_file_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    scan_url_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    scan_domain_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    scan_ip_url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

    # VT Report URLs
    get_file_report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    get_url_report_url = 'https://www.virustotal.com/vtapi/v2/url/report'

    def __init__(self, key):
        try:
            current_key = self.db.execute("SELECT * FROM settings").fetchone()
            self.api_key = current_key
        except sqlite3.OperationalError:
            self.api_key = key
            self.db.execute('CREATE TABLE IF NOT EXISTS settings(apikey)')
            self.cur.execute('DELETE FROM settings')
            self.cur.execute('INSERT INTO settings VALUES ("{}")'.format(self.api_key))
            self.db.commit()
            # self.db.close()

    def scan_file(self, file):
        params = {'apikey': self.api_key}
        files = {'file': (file, open(file, 'rb'))}
        response = requests.post(self.scan_file_url, files=files, params=params)
        self.save_response(response.json(), method="filescan")

    def scan_url(self, url_to_scan):
        params = {'apikey': self.api_key, 'url': url_to_scan}
        response = requests.post(self.scan_url_url, data=params)
        self.save_response(response.json(), method="urlscan")

    def get_domain_report(self, domain):
        params = {'apikey': self.api_key, 'domain': domain}
        response = requests.get(self.scan_domain_url, params=params)
        self.save_response(response.json(), method="domainreport")

    def get_ip_report(self, ip_address):
        params = {'apikey': self.api_key, 'ip': ip_address}
        response = requests.get(self.scan_ip_url, params=params)
        self.save_response(response.json(), method="ipreport")

    def save_response(self, response, method):
        df = pd.DataFrame(response, index=[0])
        if method == "filescan":
            df.to_sql('filescanresults', self.db,  if_exists='append', index=False)
            resource = self.db.execute("SELECT resource FROM filescanresults "
                                       "ORDER BY resource DESC LIMIT 1").fetchone()[0]
            params = {'apikey': self.api_key, 'resource': resource}
            response = requests.get(self.get_file_report_url, params=params)
            print(response)
            self.save_response(response.json(), method="filereport")
        elif method == "urlscan":
            df.to_sql('urlscanresults', self.db, if_exists='append', index=False)
            resource = self.db.execute("SELECT resource FROM urlscanresults ORDER BY "
                                       "resource DESC LIMIT 1").fetchone()[0]
            params = {'apikey': self.api_key, 'resource': resource}
            response = requests.get(self.get_url_report_url, params=params)
            self.save_response(response.json(), method="urlreport")
        elif method == "domainreport":
            df.to_sql('domainreport', self.db, if_exists='append', index=False)
        elif method == "ipreport":
            df.to_sql('ipreport', self.db, if_exists='append', index=False)
        elif method == "filereport":
            df.to_sql('filereport', self.db, if_exists='append', index=False)
        elif method == "urlreport":
            df.to_sql('urlreport', self.db, if_exists='append', index=False)
        else:
            raise Exception("No such method.  Method passed was: {}".format(method))