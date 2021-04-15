# SQLite: auto generating key/values and tables
# Author: David Murphy
# Date: 2020-08-21

import sqlite3
import os
import time
import pandas as pd
from pandas import DataFrame
import csv
from collections import defaultdict
import pprint
import pickle
import _pickle

class all_sql(object):
    def __init__(self):
        self.dir_path = os.path.abspath(__file__)
        self.path = os.path.dirname(self.dir_path) + '/'
        self.vulndb = 'vdata.db'
        self.error = sqlite3.Error
        self.derror = sqlite3.DataError
        self.notsupport = sqlite3.NotSupportedError
        self.program = sqlite3.ProgrammingError
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
    @timestamp
    # file txt/json or csv/excel check
    def file_interpreter(self, file, table):
        try:
            with open(self.path + file, 'r') as f:
                s = f.read()
                self.db_exist_csv(file, table)
        except:
            self.pickling_data(file, table)
        return
    # deserailization of txt data
    @timestamp
    def pickling_data(self, file, table):
        self.pickled_load_ = pickle.load(open(self.path + file, 'rb'))
        self.db_exist_txt(self.pickled_load_, table)
        #print(self.pickled_load_)
        return
    # db check for txt data or in json format
    @timestamp
    def db_exist_txt(self, file, table):
        try:
            with open(self.path + self.vulndb, 'rb') as f: pass
            self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
            self.vuln_c = self.vuln_conn.cursor()
            self.db_generation_txt(file, table)
        except:
            print('table or db doesnt exist')
            self.db_generation_txt(file, table)
        return
    # db check for csv data
    @timestamp
    def db_exist_csv(self, file, table):
        try:
            with open(self.path + self.vulndb, 'rb') as f: pass
            self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
            self.vuln_c = self.vuln_conn.cursor()
            self.file_cleanup(file, table)
        except:
            print('table or db doesnt exist')
            self.file_cleanup(file, table)
        return
    # generating sql tables for txt data or in json format
    @timestamp
    def db_generation_txt(self, file, table):
        try:
            with open(self.path + self.vulndb, 'rb') as f: pass
            self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
            self.vuln_c = self.vuln_conn.cursor()
            for x in file:
                self.keys = x.keys()
            column_create = ' TEXT, '.join(self.keys) + ' TEXT'
            i = f'CREATE TABLE {table} ({column_create});'
            #to troubleshoot table creation, print(i)
            self.vuln_c.execute(i)
            self.vuln_conn.commit()
            self.vuln_conn.close()
            self.db_appending_txt(file, table)
        except self.error as e:
            print(f'{type(e).__name__} in sql appending')
            print(e)
            table = table + 'dup'
            self.db_generation_txt(file, table)
        return
    # invalid char cleanup
    @timestamp
    def file_cleanup(self, file, table):
        try:
            with open(self.path + file, 'r') as f:
                file_raw = f.read()
                #replace bad stuff in csv
                for line in file_raw:
                    #x.replace('"','')
                    f.close()
            self.db_generation_csv(file, table)
        except:
            print('your file is clean')
            self.db_generation_csv(file, table)
        return 
    # generating sql tables for csv file
    @timestamp
    def db_generation_csv(self, file, table):
        try:
            with open(self.path + self.vulndb, 'rb') as f: pass
            self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
            self.vuln_c = self.vuln_conn.cursor()
            with open(self.path + file, 'r') as f:
                file_raw = f.read()
            split_char = '\r\n' if '\r\n' in file_raw else '\n'
            self.file_split = file_raw.split(split_char)
            headers_raw = self.file_split[0]
            self.headers = headers_raw.split(',')
            columns = ' TEXT,'.join([f'"{x}"' for x in self.headers])
            i = f'CREATE table IF NOT EXISTS {table} ( {columns})'
            #to troubleshoot table creation, print(i)
            #print(i)
            self.vuln_c.execute(i)
            self.vuln_conn.commit()
            self.db_appending_csv(table)
        except self.error as e:
            print(f'{type(e).__name__} in sql appending')
            print(e)
            self.db_appending_csv(table)
        except:
            print('could not create your db')
        return
    # appending data to sql values for txt formatting
    @timestamp
    def db_appending_txt(self, file, table):
        self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
        self.vuln_c = self.vuln_conn.cursor()
        #print(file)
        for line in file:
            try:
                if not line: continue
                #
                #line_split = line.split(',')
                #d = dict(zip(self.keys,line_split))
                #
                keys = list(line.keys())
                values = list(line.values())
                #
                keyst = ', '.join([x for x in keys])
                valst = ', '.join([f'"{x}"' for x in values])
                i = f'INSERT INTO {table} ({keyst}) VALUES ({valst});'
                #print(i)
                self.vuln_c.execute(i)
            except self.error as e:
                print(f'{type(e).__name__} in sql appending')
                print(e)
            except self.derror as e:
                print(f'{type(e).__name__} in sql appending')
            except self.self.notsupport as e:
                print(f'{type(e).__name__} in sql appending')
        self.vuln_conn.commit()
        self.sql_disconnect()
        return
    # appending data to sql values for csv formatting
    @timestamp
    def db_appending_csv(self, table):
        self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
        self.vuln_c = self.vuln_conn.cursor()
        for line in self.file_split[1:]:
            try:
                if not line: continue
                #
                line_split = line.split(',')
                d = dict(zip(self.headers,line_split))
                #
                keys = list(d.keys())
                values = list(d.values())
                #
                keyst = ', '.join([f'"{x}"' for x in keys])
                valst = ', '.join([f'"{x}"' for x in values])
                i = f'INSERT INTO {table} ({keyst}) VALUES ({valst});'
                self.vuln_c.execute(i)
            except self.error as e:
                print(f'{type(e).__name__} did you really have to use spaces or commas')
                print(e)
            except self.derror as e:
                print(f'{type(e).__name__} in sql appending')
            except self.self.notsupport as e:
                print(f'{type(e).__name__} in sql appending')
        self.vuln_conn.commit()
        self.sql_disconnect()
        return
    # establish sql cursor
    @timestamp
    def sql_connect(self):
        self.vuln_conn = sqlite3.connect(self.path + self.vulndb)
        self.vuln_c = self.vuln_conn.cursor()
        return
    # commit and close sql cursor
    @timestamp
    def sql_disconnect(self):
        self.vuln_conn.commit()
        self.vuln_conn.close()
        return
    # specific test query
    @timestamp
    def sql_query_atable(self, table):
        self.check = self.vuln_c.execute(f'SELECT * FROM {table}')
        self.result = self.check.fetchall()
        print(f'example result of {table}:\n{self.result[0]}')
    
if __name__ == '__main__':
   all_sql = all_sql()
   test =  all_sql.file_interpreter('psirtjunk.txt', 'test_cisco_vuln')
   #
