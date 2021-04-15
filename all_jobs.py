## Vulnerbility Investigation Automation (VIA)
# Author: David Murphy
# Date: 2020-08-21

# importing all programs
from vuln import *
from all_sql import *
from datetime import datetime
now = datetime.now()
today = now.strftime('20%y_%m_%d')

# referencing all programs:
vuln = vuln()
all_sql = all_sql()

#   Cisco psirt vulnerbilities
#       * two seperate data stores: vulns & products for sql pri_key relating
#
psirt_data = vuln.auth(f'cisco_vuln{today}.txt', f'cisco_products{today}.txt')
cisco_vuln = all_sql.file_interpreter(f'cisco_vuln{today}.txt', f'cisco_vuln{today}')
cisco_vulns = all_sql.file_interpreter(f'cisco_products{today}.txt', f'cisco_products{today}')
