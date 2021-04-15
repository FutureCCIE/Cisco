## Cisco psirt vulnerbility data retrevial and storing
#### This development of Cisco psirt automation, allows users the ability to pull live vulnerability (cve) data from Cisco's repository.

Requirements:
##### 0. Creation of an account with Cisco
##### 1. Registering of an polling source with Cisco 
##### 2. Generate or create access method (i.e. shared secret/key) with registered applicaiton.

This script simplifies auth, data retrevial, and storing. 
In addition, there is an option to utilize sqlite3 and a database, for structured psirt vuln data storing.


### How to run:
##### requires python 3.x
###### 0. The scripts allows data storing and cred retrevial to be done in the native directory of which the script is running, you can manual modify this if you so choose.
###### 1. Verify you have SQLite DB application (https://sqlitebrowser.org/), if you desire to utilize a sql database, and correlating script 'all_sql.py'
###### 2. Verify you have all the correct py libraries installed (e.g. pip -install {libary_name}) 
###### 3. Execute main.py with python (e.g. python -i all_jobs.py) to run programs
###### 4. Optional: Import your network infrascrutures inventory into the sqlite database, and preform data comparison (i.e SQL comparison)


[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/FutureCCIE/Cisco-psirt)
