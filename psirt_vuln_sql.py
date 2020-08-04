import sqlite3
import pickle
import _pickle
import os
import time

class vuln_sql(object):
    def __init__(self):
        self.path = 'C:/Users/'
        self.adv_list = '_vuln_output_.txt'
        self.vulndb = 'something.db'
        self.table_1 = 'cisco_vuln_adv'
        self.table_3 = 'cves'
        self.table_4 = 'product_Names'
        return
    # function legnth time in ms
    def timestamp(method):
       def wrapper(*args, **kwargs):
              ts = time.time()
              result = method(*args, **kwargs)
              te = time.time()
              #print 'NOTE: function ({}) ran for {}ms to finish'.format(method.__name__, args, int((te-ts) * 1000))
              print('[I] {} took {}ms to complete standby for next instructions'.format(method.__name__, int((te-ts) * 1000)))
              return result
       return wrapper
    # loading serialized data into dict
    @timestamp
    def pickling_(self):
        self.pickled_load_ = pickle.load(open(self.path + self.adv_list, 'rb'))
        for x in self.pickled_load_[0:]:
            self.keys = x.keys()
        self.db_exist()
        return
    # checks for sql db, continues if exist
    @timestamp
    def db_exist(self):
        try:
            with open(self.path + self.vulndb, 'rb') as f: pass
            self.sql_connect()
        except:
            self.sql_generation()
        return
    # generates sql tables and connects (if intial)
    @timestamp
    def sql_generation(self):
        with open(self.path + self.vulndb, 'wb') as f: pass
        self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
        self.vuln_c = self.vuln_conn.cursor()
        #print(self.keys)
        column_create = ' TEXT, '.join(self.keys) + ' TEXT'
        self.create_query = f'CREATE TABLE {self.table_1} ({column_create});'
        self.vuln_c.execute(self.create_query)
        self.vuln_c.execute('''CREATE TABLE cves (cves text)''')
        self.vuln_c.execute('''CREATE TABLE product_Names (product_Names text)''')
        self.vuln_conn.commit()
        self.vuln_conn.close()
        self.sql_appending_vuln()
        return
    # establish sql cursor
    @timestamp
    def sql_connect(self):
        self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
        self.vuln_c = self.vuln_conn.cursor()
        self.sql_appending_vuln()
        return
    # appending stuff to db - cves and product
    @timestamp
    def sql_appending_vuln(self):
        self.vuln_conn = sqlite3.connect(self.path + self.vulndb)  
        self.vuln_c = self.vuln_conn.cursor()
        self.cves_dict = []
        for x in self.pickled_load_:
            self.y = x['cves']
            self.cves_dict.append(self.y)
            self.tt = list(self.cves_dict)
            for x in self.tt[0:]:
                y = x[0:]
                self.cve_insert = f'INSERT INTO cves (cves) VALUES ("{y}")'
            self.vuln_c.execute(self.cve_insert)
            self.vuln_conn.commit()
        self.device_dict = []
        for x in self.pickled_load_:
            self.p = x['product_Names']
            self.device_dict.append(self.p)
            self.ff = list(self.device_dict)
            for x in self.ff[0:]:
                y = x[0:]
                self.device_insert = f'INSERT INTO product_Names (product_Names) VALUES ("{y}")'
            self.vuln_c.execute(self.device_insert)
            self.vuln_conn.commit()
        self.check = self.vuln_c.execute(f'SELECT * FROM cves')
        self.check = self.vuln_c.execute(f'SELECT * FROM product_names')
        self.result = self.check.fetchall()
        self.sql_query()
        return
    # specific querying for data
    @timestamp
    def sql_query(self):
        self.query = (
        f'INSERT INTO joined (cves, product_Names) VALUES ('
        f'( SELECT id FROM cves WHERE name = "{self.tt}")'
        f'( SELECT id FROM product_Names WHERE name = "{self.ff}")'
        f')' )
        self.vuln_c.execute(self.query)
        self.vuln_conn.commit()
        r = self.vuln_c.execute(f'SELECT * FROM {self.table_4};')
        s = self.vuln_c.execute(f'SELECT * FROM {self.table_3};')
        self.result = r.fetchall()
        self.result = s.fetchall()
        print(self.results)
        return

if __name__ == '__main__':
   vuln_sql = vuln_sql()
   pick = vuln_sql.pickling_()
   ex = vuln_sql.db_exist()
   gen = vuln_sql.sql_generation()
   ape = vuln_sql.sql_appending_vuln
   q = vuln_sql.sql_query()
   sql_run = vuln_sql, pick, ex, gen, ape, q
   

