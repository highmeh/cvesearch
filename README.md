# cvesearch
Offline CVE Search utility.

(Prereqs: pip3 install requests untangle)


Usage:



./cvesearch.py -h

  Display the help menu
  
./cvesearch.py -c 2017-0199

  Search by CVE number. Search any part of the CVE (CVE-2017-0199, 2017-0199, or 0199).

./cvesearch.py -s "Windows 2012 R2"

  Search all CVE descriptions by keyword. Use quotations for multi-word search.
  
./cvesearch.py -d 

  Download or update CVE database to cve_db.xml. Internet connection required.
