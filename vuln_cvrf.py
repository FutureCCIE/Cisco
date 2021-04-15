# Cisco psirt cvrf url grabbing and xml storing
# Author: David Murphy
# Date: 2021-02-11

import requests
from http.client import HTTPSConnection
from requests.auth import HTTPBasicAuth
from base64 import b64encode
import urllib.request
import urllib3
urllib3.disable_warnings()
import time
import pickle
import _pickle
import os
from datetime import datetime
import sqlite3

class vuln_cvrf(object):
    # initial stuff
    def __init__(self):
        day = datetime.now().day
        month = datetime.now().month
        year = datetime.now().year
        config_file = 'configuration.json'
        self.path = os.path.abspath(__file__)
        self.dir_path = os.path.dirname(self.path)
        self.prox = {}
        self.vulndb = 'vdata.db'
        self.error = sqlite3.Error
        self.derror = sqlite3.DataError
        self.notsupport = sqlite3.NotSupportedError
        self.program = sqlite3.ProgrammingError
        self.parms = {}
        return
    # database connect cursor
    def connect(self):
        self.vuln_conn = sqlite3.connect(self.dir_path + f'/{self.vulndb}')
        self.vuln_c = self.vuln_conn.cursor()
        return
    # commit and close database cursor
    def disconnect(self):
        self.vuln_conn.commit()
        self.vuln_conn.close()
        return
    # sql query for cvrf urls to pass to request get
    def query_sql(self, table):
        self.connect()
        self.check = self.vuln_c.execute(f'SELECT cvrf_Url FROM {table}')
        self.result = self.check.fetchall()
        for x in self.result:
            if x[0] != 'NA':
                yo = x[0].split('/')
                title = yo[7]
                self.cvrf_Url_connect(x[0], title)
            else:
                continue
        self.disconnect()
        return   
    # connect and pull xml data from cvrf site
    def cvrf_Url_connect(self, xml_site, title):
        requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.Session()
        response = requests.get(url=f'{xml_site}', verify=False, params=self.parms, proxies=self.prox,)
        if response.status_code == 200 or 202:
            result = response.text
            self.pickling(result, title)
        elif response.status_code != 200 or 202:
            print(response.status_code)
            return
    # searlize data
    def pickling(self, result, title):
        if len(result) != 0:
            self.file  = open(self.dir_path + f'/{title}.xml', 'wb')
            dump = pickle.dump(result, self.file)
            self.file.close()
        elif len(self.result) == 0:
            print(f'nothing here boss')
        return
            
if __name__ == '__main__':
    vuln_cvrf = vuln_cvrf()
   #test = vuln_cvrf.query_sql('cisco_vuln1022021')
   # insert your sql table, and the retrieval and storing will begin
