#!/usr/bin/env python3
import argparse
import os.path
import untangle
from requests import get


local_cve_db = "cve_db.xml"


def downloaddb():
	if os.path.isfile(local_cve_db):
		print("[-] CVE Database exists.")
		exit()
	else:
		print("[+] Downloading cve_db.xml. This may take a few minutes.")
		with open(local_cve_db, 'wb') as file:
			response = get('https://cve.mitre.org/data/downloads/allitems.xml')
			file.write(response.content)
			print("[+] Complete!")
			file.close()

def cvenumber_search(cvenumber):
	obj = untangle.parse(local_cve_db)
	print("[+] Searching for {0}, this may take a minute...".format(cvenumber))

	o = untangle.parse(local_cve_db)
	for item in o.cve.item:
		name = item['name']
		desc = item.desc.cdata
		reference = item.refs

		if cvenumber in name.lower():
			print("\033[1m" + "\n[+] Match found:\n----------------")
			print("\033[1m" + "[+] CVE ID: " + "\033[0m" + "{0}".format(name))
			print("\033[1m" + "[+] CVE Description: " + "\033[0m" + "{0}".format(desc))
			try:
				for url in reference.ref:
					print("\033[1m" + "[+] Reference: " + "\033[0m" + "{0}".format(url.cdata))
			except:
				print("[-] No references available for {0}".format(name))


def keyword_search(searchtext):
	obj = untangle.parse(local_cve_db)
	print("[+] Searching for {0}, this may take a minute...".format(searchtext))

	o = untangle.parse(local_cve_db)
	for item in o.cve.item:
		name = item['name']
		desc = item.desc.cdata
		reference = item.refs

		if searchtext in desc.lower():
			print("\033[1m" + "\n[+] Match found:\n----------------")
			print("\033[1m" + "[+] CVE ID: " + "\033[0m" + "{0}".format(name))
			print("\033[1m" + "[+] CVE Description: " + "\033[0m" + "{0}".format(desc))
			try:
				for url in reference.ref:
					print("\033[1m" + "[+] Reference: " + "\033[0m" + "{0}".format(url.cdata))
			except:
				print("\033[1m" + "[-] No references available for " + "\033[0m" + "{0}".format(name))


progdesc = "cvesearch allows for offline searching of CVEs."
parser = argparse.ArgumentParser(description=progdesc)
parser.add_argument('-d', action='store_true', default='False', 
                    help='Download the CVE Database.')
parser.add_argument('-c', metavar='CVE Number', action='store', 
                    help='Search by CVE Number')
parser.add_argument('-s', metavar='Search Term', action='store', 
					help='Search by CVE keyword')
args = parser.parse_args()

if args.d is True:
	downloaddb()

if args.c:
	cvenumber = args.c
	if os.path.isfile(local_cve_db):
		print("[+] Parsing CVE data...")
		cvenumber_search(cvenumber.lower())
	if not os.path.isfile(local_cve_db):
		print("[-] CVE Database is missing. Downloading...")
		downloaddb()

elif args.s:
	searchtext = args.s.lower()
	if os.path.isfile(local_cve_db):
		print("[+] Parsing CVE data...")
		keyword_search(searchtext)
	if not os.path.isfile(local_cve_db):
		print("[-] CVE Database is missing. Downloading...")
		downloaddb()
