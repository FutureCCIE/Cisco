[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/FutureCCIE/Cisco-psirt)
## Cisco psirt vulnerbility data retrevial and storing
#### This development of Cisco psirt vulnerability automation, provides the ability to pull live vulnerability data from Cisco's repository.
##### Data retrieved from cisco psirt vuln: 
###### Advisory Id, Advisory Title, Bug IDs, ipsSignatures, cves, cwes, cvssBaseScore, sir, cvrfUrl, firstPublished, lastUpdated, publicationUrl, and productNames.

#### Requirements:
###### 0. Cisco [[API CONSOLE](https://apiconsole.cisco.com/)] account registration
###### 1. Create and register the application you will be using.
###### 2. Generate or create access method (i.e. shared secret/key) with registered applicaiton.

This script simplifies auth, data retrevial, and storing. 
In addition, there is an option to utilize sqlite3 and a database, for structured psirt vuln data storing.

#### How to run:
##### requires python 3.x
###### 0. The scripts allows data storing and cred retrevial to be done in the native directory of which the script is running, you can manually modify it if you so choose.
###### 1. Verify you have SQLite DB application (https://sqlitebrowser.org/), if you desire to utilize a sql database, and correlating script 'all_sql.py'
###### 2. Verify you have all the correct py libraries installed (e.g. pip -install {libary_name}) 
###### 3. Execute main job with python (e.g. python -i all_jobs.py) to run programs
###### 4. Optional: Import your network infrascrutures inventory into the sqlite database, and preform data comparison (i.e SQL comparison)

#### Additional 
###### Running 'vuln_cvrf.py' requires the use of the Sqlite DB referenced earlier. If this script is intiated, it will download the cvrf data from Cisco for all the Vulns you stored earlier.
