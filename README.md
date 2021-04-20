[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/FutureCCIE/Cisco-psirt)
## Cisco psirt vulnerbility data retrevial and storing
#### This development of Cisco psirt vulnerability automation, provides the ability to pull live vulnerability data from Cisco's repository.

#### Pre-Requirements:
0. Cisco [[API CONSOLE](https://apiconsole.cisco.com/)] account registration
1. Register the application you will be using.
2. Create access method (i.e. shared secret/key) with registered applicaiton.
3. Install Python 3.x
4. Verify you have all the correct Python libraries installed e.g. 
``` pip -install {libary_name}  ```

#### Requirements:
0. Copy all the files from the repo into the directory/folder you will be running the python in.
1. configuration.json: used for cred storing. Please keep the same formatting as listed in the example, and provided below
``` {
"servers": {
        "cisco": {
			"psirt_key" : "_KEY_",
      "psirt_secret" : "_SECRET_"
        }
    }
	
} 
```
2. Verify you have SQLite DB application (https://sqlitebrowser.org/), if you desire to utilize a sql database, and correlating script 'all_sql.py'
3. Execute main job with python to run program
``` python -i all_jobs.py ```
4. Optional: Import your network infrascrutures inventory into the sqlite database, and preform data comparison (i.e SQL comparison)
5. Nugget: Running vuln_cvrf.py requires the use of the Sqlite DB referenced earlier. If this script is intiated, it will iniate the download of cvrf data from Cisco for all the Vulns you stored earlier, into a searlized xml format.
6. Nugget: You can pass the ```all_sql.py``` class any file type: csv, txt, searlized, and it will extract the data into key/value pairs and store the data in the desired database table.

#### How it works
This script simplifies auth, data retrevial, and storing. 
In addition, there is an option to utilize sqlite3 and a database, for structured psirt vuln data storing and data relating. This will allow the storing of vulnerbility data for all vulnerabilities that have been released in the past 5 years, via Cisco.

#### What the code does:
``` vuln.py ```
0. Configuration.json is used for cred storing
1. Auth with cisco oauth, token retrieval
2. Token auth and get data with cisco endpoint
3. Data sent to two parsing functions: 
  - first compiles the data into a formatting with the vulnerability code as the primary key, and appending each product additionally 1NF formatting (could be useful for data comparison)
  - second compiles the data in a easy viewing parsing format, but non SQL NF.
4. Searlizes the data with pickle and stores as an outputfile, which can be desearlized/opened and interpreted at will.

``` all_sql.py ```
0. De-searlizes the stored data into .txt formatting
1. Validation of database existance
2. Auto-generation of sql table. As listed in the ```all_jobs.py```  the first value passed into all_sql.file_interpreter() is the previously searlized data, the second is what your table name will be in sql.
``` test = all_sql.file_interpreter('searlized_data.txt', 'My_SQLITE_TABLE') ```
3. Post the table generation, the script will auto-append the data to the newly created table (execute), and save the database config.
