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
5. Optional: Running vuln_cvrf.py requires the use of the Sqlite DB referenced earlier. If this script is intiated, it will iniate the download of cvrf data from Cisco for all the Vulns you stored earlier, into a searlized xml format.

#### How it works
This script simplifies auth, data retrevial, and storing. 
In addition, there is an option to utilize sqlite3 and a database, for structured psirt vuln data storing and data relating. This will allow the storing of vulnerbility data for all vulnerabilities that have been released in the past 5 years, via Cisco.


