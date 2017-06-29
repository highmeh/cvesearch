# cvesearch
Offline CVE Search utility.



Usage:



./cvesearch.py -h

  Display the help menu
  
./cvesearch.py -c 2017-0199

  Search by CVE number. Full text, so search CVE-2017-0199, 2017-0199, or 0199 to get results for that CVE.

./cvesearch.py -s "Windows 2012 R2"

  Search all CVE descriptions by keyword. Use quotations for multi-word search.
  
./cvesearch.py -d 

  Download CVE database to cve_db.xml. Internet connection required. Use this to force cve_db.xml updates, too.
