import requests
import sqlite3
import pandas as pd


class VtScan(object):

    def __init__(self, key):
        try:
            self.__db = sqlite3.connect("pyscan")
        except sqlite3.OperationalError as oe:
            print(f"Could not connect or create database{self.__db}: {oe}")
        self.__cur = self.__db.cursor()
        self.__api_key = key
        self.__auto_run = True

        self.scan_file_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        self.scan_url_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        self.scan_domain_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        self.scan_ip_url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        self.get_file_report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
        self.get_url_report_url = 'https://www.virustotal.com/vtapi/v2/url/report'

        if self.__api_key == '':
            try:
                current_key = self.__db.execute("SELECT * FROM settings").fetchone()
                self.__api_key = current_key
            except sqlite3.OperationalError:
                self.__api_key = key
            finally:
                self.__api_key = key
        self.__db.execute('CREATE TABLE IF NOT EXISTS settings(apikey)')
        self.__cur.execute('DELETE FROM settings')
        self.__cur.execute('INSERT INTO settings VALUES ("{}")'.format(self.__api_key))
        self.__db.commit()
        # self.db.close()

    def scan_file(self, file):
        params = {'apikey': self.__api_key}
        files = {'file': (file, open(file, 'rb'))}
        response = requests.post(self.scan_file_url, files=files, params=params)
        print(response)
        self.__save_response(response.json(), method="filescan")

    def scan_url(self, url_to_scan):
        params = {'apikey': self.__api_key, 'url': url_to_scan}
        response = requests.post(self.scan_url_url, data=params)
        self.__save_response(response.json(), method="urlscan")

    def get_domain_report(self, domain):
        params = {'apikey': self.__api_key, 'domain': domain}
        response = requests.get(self.scan_domain_url, params=params)
        self.__save_response(response.json(), method="domainreport")

    def get_ip_report(self, ip_address):
        params = {'apikey': self.__api_key, 'ip': ip_address}
        response = requests.get(self.scan_ip_url, params=params)
        self.__save_response(response.json(), method="ipreport")

    def __save_response(self, response, method):
        df = pd.DataFrame(response, index=[0])
        if method == "filescan":
            df.to_sql('filescanresults', self.__db, if_exists='append', index=False)
            resource = self.__db.execute("SELECT resource FROM filescanresults "
                                       "ORDER BY resource DESC LIMIT 1").fetchone()[0]
            params = {'apikey': self.__api_key, 'resource': resource}
            response = requests.get(self.get_file_report_url, params=params)
            print(response)
            self.__save_response(response.json(), method="filereport")
        elif method == "urlscan":
            df.to_sql('urlscanresults', self.__db, if_exists='append', index=False)
            resource = self.__db.execute("SELECT resource FROM urlscanresults ORDER BY "
                                       "resource DESC LIMIT 1").fetchone()[0]
            params = {'apikey': self.__api_key, 'resource': resource}
            response = requests.get(self.get_url_report_url, params=params)
            self.__save_response(response.json(), method="urlreport")
        elif method == "domainreport":
            df.to_sql('domainreport', self.__db, if_exists='append', index=False)
        elif method == "ipreport":
            df.to_sql('ipreport', self.__db, if_exists='append', index=False)
        elif method == "filereport":
            df.to_sql('filereport', self.__db, if_exists='append', index=False)
        elif method == "urlreport":
            df.to_sql('urlreport', self.__db, if_exists='append', index=False)
        else:
            raise Exception("No such method.  Method passed was: {}".format(method))


if __name__ == '__main__':
    virus_scan = VtScan("your_key")
    virus_scan.scan_file("c:\\save\\location\\suspectedfile.exe")
