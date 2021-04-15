# Cisco psirt vuln data pull
# Author: David Murphy
# Date: 2020-08-21

import requests
from http.client import HTTPSConnection
from requests.auth import HTTPBasicAuth
from base64 import b64encode
import urllib.request
import urllib3
urllib3.disable_warnings()
import xml
import json
import time
import pickle
import _pickle
import os
from datetime import datetime

class vuln(object):

    def __init__(self):
        now = datetime.now()
        self.today = now.strftime('20%y-%m-%d')
        self.auth_url = 'https://cloudsso2.cisco.com/as/token.oauth2'
        self.get_adv_vuln = f'https://api.cisco.com/security/advisories/all/firstpublished?startDate=2015-01-01&endDate={self.today}'
        self.prox = {}
        self.bearer_token = {}
        self._token_ = ()
        self.parms = {}
        config_file = 'configuration.json'
        self.dir_path = os.path.abspath(__file__)
        self.path = os.path.dirname(self.dir_path)
        with open(f'{self.path}/{config_file}','r') as f:
                raw_file = f.read()
                config_raw = json.loads(raw_file)
                self.key = config_raw['servers']['cisco_psirt']['psirt_key']
                self.secret = config_raw['servers']['cisco_psirt']['psirt_secret']
    # time tracker
    def timestamp(method):
       def wrapper(*args, **kwargs):
              ts = time.time()
              result = method(*args, **kwargs)
              te = time.time()
              print('[I] {} took {}ms to complete standby for next instructions'.format(method.__name__, int((te-ts) * 1000)))
              return result
       return wrapper
    # sso auth with cisco
    @timestamp
    def auth(self, fileone, filetwo):
        response = requests.post(self.auth_url, verify=False, proxies=self.prox, data={'grant_type': 'client_credentials'},
                                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                params={'client_id': self.key, 'client_secret': self.secret})
    
        if response == 200 or 202:
            res = json.loads(response.text)
            self.bearer_token.update(res)
            self.token = self.bearer_token['access_token']
            print(f'[I] psirt http-200 success, {self._token_} bearer token stored')
            print(f'[I] psirt token expires in {self.bearer_token["expires_in"]} seconds')
            self.get_adv_bulk(fileone, filetwo)
            return
        elif response != 200 or 202:
            res = json.loads(response.text)
            print(f'did not recieve expected 20X - reason{response.text}')
        return
    @timestamp
    # bulk vuln query
    def get_adv_bulk(self, fileone, filetwo):
        requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(self.get_adv_vuln, verify=False, proxies=self.prox,
        headers={'Authorization': 'Bearer {0}'.format(self.token), 'Accept': 'application/json'})
        if response.status_code == 200 or 202:
            self.outputs = json.loads(response.text)
            self.advs = self.outputs['advisories']
            self.parse_prods(self.advs, filetwo)
            self.parse_advs(self.advs, fileone)
        elif response.status_code != 200 or 202:
            print(response.status_code)
            return
        return
    @timestamp  
    def parse_prods(self, input, filetwo):
        self.temp = []
        self.d = dict()
        self.temp2 = []
        self.temp3 = []
        for line in input:
            adv = line['advisoryId']
            names = line['productNames']
            for x in names:
                self.temp.append(adv)
                self.temp.append(x)
        for x in self.temp:
            if 'cisco-' in x:
                self.d['advisoryId'] = x
                self.temp2.append(self.d)
            elif 'Cisco-' in x:
                #print(x)
                self.d['advisoryId'] = x
                self.temp2.append(self.d)
                continue
                #self.d = dict()
            elif x != 'NA':
                self.third = x
                self.d['productName'] = x
                self.temp2.append(self.d)
                self.d = dict()
            else:
                self.d = dict()
                continue
        self.pickling_(self.temp2, filetwo)
        return
    # extract relavent data
    def parse_advs(self, advs, fileone):
        adv_list_pri = []
        self.adv_list_sec = []
        for adv in advs:
            adv_dict = dict()
            self.adv_dict_key = dict()
            self.adv_dict_value = dict()
            adv_dict['advisoryId'] = adv['advisoryId'] if 'advisoryId' in adv else 'unknown'
            adv_dict['advisoryTitle'] = adv['advisoryTitle'] if 'advisoryTitle' in adv else 'unknown'
            adv_dict['bugIDs'] = adv['bugIDs'] if 'bugIDs' in adv else 'unknown'
            adv_dict['ipsSignatures'] = adv['ipsSignatures'] if 'ipsSignatures' in adv else 'unknown'
            adv_dict['cves'] = adv['cves'] if 'cves' in adv else 'unknown'
            adv_dict['cwe'] = adv['cwe'] if 'cwe' in adv else 'unknown'
            adv_dict['cvssBaseScore'] = adv['cvssBaseScore'] if 'cvssBaseScore' in adv else 'unknown'
            # need to parse better
            #adv_dict['summary'] = adv['summary'] if 'summary' in adv else 'unknown' Need to parse better
            adv_dict['sir'] = adv['sir'] if 'sir' in adv else 'unknown'
            adv_dict['cvrfUrl'] = adv['cvrfUrl'] if 'cvrfUrl' in adv else 'unknown'
            adv_dict['firstPublished'] = adv['firstPublished'] if 'firstPublished' in adv else 'unknown'
            adv_dict['lastUpdated'] = adv['lastUpdated'] if 'lastUpdated' in adv else 'unknown'
            adv_dict['publicationUrl'] = adv['publicationUrl'] if 'publicationUrl' in adv else 'unknown'
            adv_dict['productNames'] = adv['productNames'] if 'productNames' in adv else 'unknown'
            adv_list_pri.append(adv_dict)
        self.pickling_(adv_list_pri, fileone)
        return
    @timestamp
    # searlize data
    def pickling_(self, adv_list, inputfile):
        if len(adv_list) >= 1:
            self.file  = open(self.path + f'/{inputfile}', 'wb')
            self.pickled_dump_ = pickle.dump(adv_list, self.file)
            self.file.close()
        elif len(self._adv_list_) == 0:
            print(f'nothing here boss')
        return
            
if __name__ == '__main__':
    vuln = vuln()
    # to run
    test = vuln.auth('outputfileone', 'outputfiletwo')
    #
    ### What this script does
    # 1. Configuration.json is used for cred storing
    # 2. Auth with cisco oauth, token retrieval
    # 3. Token auth and get data with cisco endpoint
    # 4. Data sent to two parsing functions: 
    #   a. first compiles the data into a formatting with the vulnerability code as the primary key, and appending each product additionally 1NF formatting (could be useful for data comparison)
    #   b. second compiles the data in a easy viewing parsing format, but non SQL NF.
    # 5. Searlizes the data with pickle and stores as an outputfile, which can be desearlized/opened and interpreted at will.
    
