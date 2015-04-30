#!/bin/bash
#TODO THIS: cat combined_MicrosoftPatches.txt | cut -f1,2,7 | awk -F '\t' '{print $2"\t"$1}' | tsv_combine_columns | tr '\t' ',' | sed 's/,/\t/;s/,/, /g' | table_html | table_header 
# for i in $(ls combined_*); do cat "$i" | cut -f1,7 | awk -F '\t' '{print $2"\t"$1}' | tsv_combine_columns | tr '\t' ',' | sed 's/,/\t/;s/,/, /g' | table_html | table_header > $i.table; done


TAB=$'\t'
function csv_match_column() { COL=${1-'1'}; MATCH=${2-'test'}; awk -F'\t' -v c="$COL" -v m="$MATCH" '$c ~ m'; }
function newlines2commas() { awk 'NR==1{x=$0;next}NF{x=x","$0}END{print x}'; }
function prepend_line() { sed "s~^~$@~"; } # Adds to beginning of each line
function prepend_file_line() { sed "1i\\$@"; } # Creates new first line of file
function find_ip_host() { egrep -o "([0-9]{1,3}\.){3}[0-9]{1,3}( \([^)]*\))?"; }
function find_links() { perl -nle 'print $1 while /(https?:\/\/[^\(\)<>\"'\''\\,:;\s]+)/g'; }

if [ $# -lt 1 ]
then
  echo "Usage: `basename $0` {Finding Title to Match (ie: Apache)} {Match REGEX}"
  echo "Process Nessus .nessus files"
  echo "Usage: Place any number of *.nessus files in the directory and rerun"
  exit 1
fi
FILECOUNT=$(ls -1 *.nessus 2>/dev/null | wc -l)
if [[ $FILECOUNT == 0 ]]
then 
  echo "Process Nessus .nessus files"
  echo "Usage: Place any number of *.nessus files in the directory and rerun"
  exit 2
fi 


NAME=${1:-"Apache"}
MATCH=${2:-$NAME} # For a regex instead of a Title
INFILE="out/combined_$NAME.txt"
METASPLOIT_DIR="/pentest/exploits/framework"
#CVSSGEN='./openCVSS-ph/openCVSS-tester.py'
mkdir out 2>/dev/null

#echo "# Combining all medium and high '$NAME' ($MATCH) findings into a single finding"

#MSF=$(grep -r "CVE[^-]" "/pentest/exploits/framework/modules/" | grep -v '.svn' | sed 's/:[^0-9]*\([0-9-]*\).*/\tCVE-\1/')
#alias cve2link='sed '\''s#\(CVE-[0-9]*-[0-9]*\)#<a href="http://www.cvedetails.com/cve-details.php?t=1\&cve_id=\1">\1</a>#ig'\'''
#function cve2cvss() { xmlstarlet sel -N x="http://scap.nist.gov/schema/feed/vulnerability/2.0" -N cvss="http://scap.nist.gov/schema/cvss-v2/0.2" -N vuln="http://scap.nist.gov/schema/vulnerability/0.4" -T -t -m /x:nvd/x:entry -v @id -o '&#09;CVSSv2 ' -m vuln:cvss/cvss:base_metrics -v cvss:score -o " (AV:" -v 'substring(cvss:access-vector,1,1)' -o "/AC:" -v 'substring(cvss:access-complexity,1,1)' -o "/Au:" -v 'substring(cvss:authentication,1,1)' -o "/C:" -v 'substring(cvss:confidentiality-impact,1,1)' -o "/I:" -v 'substring(cvss:integrity-impact,1,1)' -o "/A:" -v 'substring(cvss:availability-impact,1,1)' -o ")"  -b -n *.xml | sort -Vu ; } # NVDCVSS Score Parsing

xmlstarlet sel -T -t -m NessusClientData_v2/Report/ReportHost -v "HostProperties/tag[@name='host-ip']" -o '&#09;' -v "HostProperties/tag[@name='dns-name']" -o '&#09;' -v "str:replace(HostProperties/tag[@name='operating-system'],'&#10;',', ')" -m "ReportItem" -n -o '&#09;' -v @port -o '/' -v @protocol -o '&#09;' -v @svc_name -o '&#09;' -o '&#09;' -v @pluginName -o '&#09;' -v @pluginFamily -o '&#09;' -v @pluginID -o '&#09;' -i '@severity=3' -o 'High' -b -i '@severity=2' -o 'Medium' -b -i '@severity=1' -o 'Low' -b -i '@severity=0' -o 'Info' -b -o '&#09;' -v "str:replace(synopsis,'&#10;',' ')" -o '&#09;' -v "str:replace(description,'&#10;',' ')" -o '&#09;' -v "str:replace(solution,'&#10;',' ')" -o '&#09;' -v cvss_base_score -o ' ' -v cvss_vector -b -n *.nessus | awk 'BEGIN {h="[ERROR]"}{if (/^\t/) printf("%s%s\n",h,$0); else h=$0;}' | sort -Vu | grep -e "${TAB}Critical${TAB}" -e "${TAB}High${TAB}" -e "${TAB}Medium${TAB}" | csv_match_column 7 "$MATCH" > $INFILE
ISSUES=$(cat $INFILE | cut -f7 | sort -Vu)

TITLE="Multiple $NAME Vulnerabilities"
DESCRIPTION="Multiple publicly disclosed vulnerabilities exist in outdated versions of $NAME that may allow for complete system compromise without authentication or detailed knowledge of the issue."
CVSS=$(cat $INFILE | cut -f14 | sort -uVr | head -n1)
CVSSV=$(echo $CVSS | cut -d'#' -f2)
#CVSS_ENG=$(python $CVSSGEN $CVSSV)
CVSS_ENG="DESCRIPTION TODO"
MS=$(egrep -io "MS[0-9]*-[0-9]*" $INFILE | sort -uV | newlines2commas | prepend_line "Microsoft Security Bulletin: " | grep --color=never "MS")
BID=$(grep -i "http://www.securityfocus.com/bid/[0-9]*" $INFILE | grep -o [0-9]* | sort -nu | newlines2commas | prepend_line "BID: " | grep --color=never '[0-9]')
#CVE=$(grep -io "CVE-[0-9]*-[0-9]*" $INFILE  | sort -uV | newlines2commas | prepend_line "CVE: " | grep --color=never '[0-9]')
CVE_MSF=$(grep -io "CVE-[0-9]*-[0-9]*" $INFILE  | sort -uV) # Check if empty
CVE=$(echo "$CVE_MSF" | newlines2commas | prepend_line "CVE: " | grep --color=never '[0-9]')
# Should be able to lookup highest CVSS from database/query using CVE list
IAVA=$(egrep -io "[0-9]{4}-[AB]-[0-9]{4}" $INFILE  | sort -uV  | newlines2commas | prepend_line "IAVA Ref Number: " | grep --color=never '[0-9]' | grep -v '^$')
OSVDB=$(grep -io "OSVDB:[0-9]*" $INFILE  | grep -o "[0-9]*" | sort -uV  | newlines2commas | prepend_line "OSVDB: " | grep --color=never '[0-9]' | grep -v '^$')
SECUNIA=$(grep -io "Secunia:[0-9]*" $INFILE | grep -o "[0-9]*" | sort -uV | newlines2commas | prepend_line "Secunia: " | grep --color=never '[0-9]' | grep -v '^$')
#ALSO=$(echo -n "See Also:\nhttp://www.exploitsearch.net/index.php?q=$NAME\nhttp://www.shodanhq.com/exploits?q=$NAME\nhttp://www.itsecdb.com/oval/google-search-results.php?cx=partner-pub-9597443157321158%3Af8t3ae-e63f&cof=FORID%3A9&q=$NAME\nhttp://cvedetails.com/google-search-results.php?cx=partner-pub-9597443157321158%3Advjtec-wfv5&cof=FORID%3A9&q=$NAME\nhttp://www.google.com/search?num=100&q=site%3Awww.securityfocus.com%2Fbid%2F+$NAME\nhttp://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=$NAME" | grep -v "^$")
#EXPLOITS=$(echo "$CVE_MSF" | sed 's/CVE-//i' | grep -l -r -f - "$METASPLOIT_DIR/modules/" | grep -v -e "^$" -e ".svn" | sed 's#.*exploits/#exploit/#;s/.rb$//' | grep -v -e '/dos/' -e '/sqli' -e '/spoof/' -e '/scanner/' -e 'apache' | prepend_line "MSF: ")
EXPLOITS=''
ALSO=$(echo -n "See Also:\n$EXPLOITS\nhttp://cvedetails.com/google-search-results.php?cx=partner-pub-9597443157321158%3Advjtec-wfv5&cof=FORID%3A9&q=$NAME\nhttp://www.exploitsearch.net/index.php?q=$NAME\nhttp://www.shodanhq.com/exploits?q=$NAME\n" | grep -v "^$")

ASSIGN=$(echo -ne "$MS\n$BID\n$CVE\n$IAVA\n$OSVDB\n$SECUNIA\n" | grep -v '^$')
DESCRIPTION=$(echo -ne "$DESCRIPTION\n$CVSS\n$ASSIGN\n$ALSO")

SYSTEMS=$(cat $INFILE | find_ip_host | grep -v "^[0-9]\." | sort -uV) # Single digit starting IPs are false positives
RECOMMENDATION="Ensure these systems have been patched for critical vulnerabilities. Software updates and other mitigation strategies for have been released to address these issues which are available from the vendor and should be installed on all applicable devices."
REFERENCES=$(cat "$INFILE" | find_links | grep -iv -e "http://www.securityfocus.com/bid" -e "http://www.microsoft.com/technet/security/bulletin/" | sort -u | prepend_file_line "References:")
#RECOMMENDATION=$(echo -ne "$RECOMMENDATION\n\n$REFERENCES\n")

echo "$TITLE" > "out/finding_$NAME.txt"
echo "" >> "out/finding_$NAME.txt"
echo "$CVSS_ENG" >> "out/finding_$NAME.txt"
echo "" >> "out/finding_$NAME.txt"
echo "$RECOMMENDATION" >> "out/finding_$NAME.txt"
echo "" >> "out/finding_$NAME.txt"
echo "$DESCRIPTION" >> "out/finding_$NAME.txt"
echo "" >> "out/finding_$NAME.txt"
#echo "$SYSTEMS" >> "out/finding_$NAME.txt"
echo "$SYSTEMS" | awk -F "\t" '{ printf "<tr>"; for(i=1;i<=NF;i++) {printf "<td><p>%s</p></td>",$i;} print "</tr>" }' | sed 's#<p></p>##g' | sed "1i\<table align='center'><tbody><tr><td>Affected Resources</td></tr>" | sed '$a\</tbody></table>' >> "out/finding_$NAME.txt"
echo "" >> "out/finding_$NAME.txt"
echo "$REFERENCES" >> "out/finding_$NAME.txt"
echo "" >> "out/finding_$NAME.txt"


# Check to establish hosts with stray issues arn't combined in larger finding:
SANITY_CHECK=$(cat $INFILE | find_ip_host | grep -v "^[0-9]\." | sort | uniq -c | sort -nr | sed 's/^ *//;s/ /\t/' | prepend_file_line "# Host Count Sanity Check:" ) 
echo "$SANITY_CHECK" > "out/host_sanity_$NAME.txt"
echo "$ISSUES" | prepend_file_line "# List of Combined Issues:" > "out/issues_$NAME.txt"

echo "# Combining all critical, high and medium findings for '$NAME' ($MATCH), verify using issues_$NAME.txt and host_sanity_$NAME.txt"
#echo "# List of combined issues is in out/issues_$NAME.txt. Please confirm the count of each host in /out/host_sanity_$NAME.txt is relatively the same"

