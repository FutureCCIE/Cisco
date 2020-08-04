
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

class cisco_vuln(object):
    # initial stuff
    def __init__(self):
        self.client_key = '__REDACTED__'
        self.client_secret = '__REDACTED__'
        self.auth_url = 'https://cloudsso2.cisco.com/as/token.oauth2'
        self.get_url = 'https://api.cisco.com/security/advisories'
        self.advisories_all = '/all'
        self.sev_path = '/severity/?severity={0}'
        self.ios_path = '/ios/?version={0}'
        self._time_ = '/firstpublished?startDate=2010-01-01&endDate=2020-06-08'
        self.get_adv_vuln = self.get_url + self.advisories_all + self._time_
        self.get_sev_vuln = self.get_url + self.sev_path
        self.get_ver_vuln = self.get_url + self.ios_path
        self.get_sev_ver_vuln = self.get_url + self.sev_path + self.ios_path
        self.prox = {}
        self.bearer_token = {}
        self._token_ = ()
        self.path = 'C:/Users/david.murphy/documents/Python/'
    # time tracker
    def timestamp(method):
       def wrapper(*args, **kwargs):
              ts = time.time()
              result = method(*args, **kwargs)
              te = time.time()
              #print 'NOTE: function ({}) ran for {}ms to finish'.format(method.__name__, args, int((te-ts) * 1000))
              print('[I] {} took {}ms to complete standby for next instructions'.format(method.__name__, int((te-ts) * 1000)))
              return result
       return wrapper
    # sso auth with cisco
    @timestamp
    def get_bearer_token(self):
        response = requests.post(self.auth_url, verify=False, proxies=self.prox, data={'grant_type': 'client_credentials'},
                                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                params={'client_id': self.client_key, 'client_secret': self.client_secret})
    
        if response == 200 or 202:
            res = json.loads(response.text)
            self.bearer_token.update(res)
            self.token = self.bearer_token['access_token']
            self._token_ = self.token
            print(f'20X, success token {self._token_} stored in dict _token_')
            print(f'token expires in {self.bearer_token["expires_in"]} seconds')
            return
        elif response != 200 or 202:
            res = json.loads(response.text)
            print(f'did not recieve expected 20X - reason{response.text}')
        return
    @timestamp
    # bulk vuln query
    def get_adv_bulk(self):
        requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(self.get_adv_vuln, verify=False, proxies=self.prox,
        headers={'Authorization': 'Bearer {0}'.format(self._token_), 'Accept': 'application/json'})
        if response.status_code == 200 or 202:
            self._output_ = json.loads(response.text)
            self.advs = self._output_['advisories']
            self.parsing_(self.advs)
        elif response.status_code != 200 or 202:
            print(response.status_code)
            return
        return
    @timestamp  
    # extract relavent data
    def parsing_(self, advs):
        self._adv_list_ = []
        for adv in self.advs[0:]:
            adv_dict = dict()
            adv_dict['advisory_id'] = adv['advisoryId'] if 'advisoryId' in adv else 'Unknown'
            adv_dict['advisory_title'] = adv['advisoryTitle'] if 'advisoryTitle' in adv else 'Unknown'
            adv_dict['bug_ids'] = adv['bugIDs'] if 'bugIDs' in adv else 'Unknown'
            adv_dict['first_fixed'] = adv['firstFixed'] if 'firstFixed' in adv else 'Unknown'
            adv_dict['latest_fixed'] = adv['latestFixed'] if 'latestFixed' in adv else 'Unknown'
            adv_dict['sir'] = adv['sir'] if 'sir' in adv else 'Unknown'
            adv_dict['platform'] = adv['platform'] if 'platform' in adv else 'Unknown'
            adv_dict['cves'] = adv['cves'] if 'cves' in adv else 'Unknown'
            adv_dict['cvrf_Url'] = adv['cvrfUrl'] if 'cvrfUrl' in adv else 'Unknown'
            adv_dict['first_Published'] = adv['firstPublished'] if 'firstPublished' in adv else 'Unknown'
            adv_dict['product_Names'] = adv['productNames'] if 'productNames' in adv else 'Unknown'
            self._adv_list_.append(adv_dict)
        self.pickling_()
        return
    @timestamp
    # searlize data
    def pickling_(self):
        if len(cisco_vuln._adv_list_) >= 1:
            self.file  = open(self.path + '_vuln_output_.txt', 'wb')
            self._pickled_dump_ = pickle.dump(self._adv_list_, self.file)
            self.file.close()
        elif len(cisco_vuln._adv_list_) == 0:
            print(f'soo much empy in your list')
        return
    
if __name__ == '__main__':
    cisco_vuln = cisco_vuln()
    get_bearer_token = cisco_vuln.get_bearer_token()
    get_adv_bulk = cisco_vuln.get_adv_bulk()
    parsing_ = cisco_vuln.parsing_(cisco_vuln.advs)
    pickled = cisco_vuln.pickling_()
    test_run = cisco_vuln, get_bearer_token, get_adv_bulk
   # _pickled_load_ = cisco_vuln._pickled_load_
   # _pickled_dump_ = cisco_vuln._pickled_dump_
    
