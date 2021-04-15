# Cisco psirt vulnerbility data retrevial and storing
### This development of Cisco psirt automation, allows users the ability to pull live vulnerability (cve) data from Cisco's repository.

Requirements:
### * Creation of an account with Cisco
### * Registering of an polling source with Cisco 
### * Generate or create access method (i.e. shared secret/key) with registered applicaiton.

This script simplifies auth, data retrevial, and storing. 
In addition, there is an option to utilize sqlite3 and a database, for structured psirt vuln data storing.


### How to run:
##### requires python 3.x
###### 1. The scripts allows data storing and cred retrevial to be done in the native directory of which the script is running, you can manual modify this if you so choose.
###### 2. Verify you have SQLite DB application (https://sqlitebrowser.org/), if you desire to utilize a sql database, and correlating script 'all_sql.py'
###### 3. Verify you have all the correct py libraries installed (e.g. pip -install {libary_name}) 
###### 4. Execute main.py with python (e.g. python -i all_jobs.py) to run programs
###### 5. Optional: Import your network infrascrutures inventory into the sqlite database, and preform data comparison (i.e SQL comparison)
