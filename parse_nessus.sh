#!/bin/bash
# Extract Hostname
# Extract version information (if avalable)
# TODO: Pull NMAP processing analysis here
# TODO: Unify IP,DNS,OS data among all rows
#xmlstarlet el -u *.nessus | sort -u

TAB=$'\t'
NL=$'\n'
OUTDIR="out"
VULN="$OUTDIR/nessus.tsv"
MSFDIR="/opt/metasploit/apps/pro/msf3" # Metasploit's framework directory in Kali

# Single dependency is xmlstarlet
if ! which 'xmlstarlet' >/dev/null; then 
	echo "# apt-get install xmlstarlet"
	exit 1 
fi
FILECOUNT=$(ls -1 *.nessus 2>/dev/null | wc -l)
if [[ $FILECOUNT == 0 ]]
then 
  echo "Process Nessus .nessus files"
  echo "Usage: Place any number of *.nessus files in the directory and rerun"
  exit 1
fi 

mkdir out

echo "# Processing all Nessus files in current directory:"
ls *.nessus

# Create a list of IP to hostnames, then merge it in with our nessus.tsv below.
xmlstarlet sel -T -t -m //ReportItem[@pluginID='46180'] -v "../HostProperties/tag[@name='host-ip']" -o $'\t' -v "../HostProperties/tag[@name='host-fqdn']" -n -v plugin_output  -n *.nessus | grep -v -e '^The' -e '^$' | sed ':a;$!N;s/\n  - /\t/;ta;P;D' | awk -F'\t' '{ for (i=2; i<NF; i++){printf "%s%s%s\n",$1,FS,$i}}' | sort -uV | awk -F '\t' '{ a[$1] = a[$1] "\t" $2 } END { for (item in a ) print item, a[item] }' | sort -uV | sed -e 's/ *\t/, /g' -e 's/, /\t/' > out/ip2host.txt

# Replaced dns-name with host-fqdn
xmlstarlet sel -T -t -m NessusClientData_v2/Report/ReportHost -v "HostProperties/tag[@name='host-ip']" -o $'\t' -v "HostProperties/tag[@name='host-fqdn']" -o $'\t' -v "str:replace(HostProperties/tag[@name='operating-system'],'&#10;',', ')" -m "ReportItem" -n -o $'\t' -v @port -o '/' -v @protocol -o $'\t' -v @svc_name -o $'\t' -o $'\t' -v @pluginName -o $'\t' -v @pluginFamily -o $'\t' -v @pluginID -o $'\t' -i '@severity=4' -o 'Critical' -b -i '@severity=3' -o 'High' -b -i '@severity=2' -o 'Medium' -b -i '@severity=1' -o 'Low' -b -i '@severity=0' -o 'Info' -b -o $'\t' -m 'cve' -v . -o ' ' -b -b -n  *.nessus | awk 'BEGIN {h="[ERROR]"}{if (/^\t/) printf("%s%s\n",h,$0); else h=$0;}' | sort -Vu | sed "1i\\#IP\tHostname\tOS\tPort\tService\t\tName\tFamily\tID\tSeverity\tCVE" > out/nessus_all.tsv

# TODO: Nessus has added some OS data in the host-ip field that does not sync up with the current processing, so we split those lines out
grep "^\(#\|[0-9]\)" out/nessus_all.tsv > out/nessus.tsv
grep -v "^\(#\|[0-9]\)" out/nessus_all.tsv > out/nessus_os.tsv

# Merge full list of hostnames which each IP
while read line; do
  IP=$(echo "$line" | cut -f1)
  HOST=$(echo "$line" | cut -f2)
  sed -i "s/^$IP\t[^\t]*/$IP\t$HOST/" out/nessus.tsv
done < out/ip2host.txt

xmlstarlet sel -T -t -m "NessusClientData_v2/Report/ReportHost" -v "HostProperties/tag[@name='host-ip']" -o $'\t' -v 'count(ReportItem[@severity=4])' -o $'\t' -v 'count(ReportItem[@severity=3])' -o $'\t' -v 'count(ReportItem[@severity=2])' -o $'\t' -v 'count(ReportItem[@severity=1])' -o $'\t' -v 'count(ReportItem[@severity=0])' -n *.nessus | sed 's/^\t/[GENERAL]\t/' | sort -V | sed "1i\\#IP Address\tCritical:4\tHigh:3\tMed:2\tLow:1\tInfo:0" > out/nessus_vuln_count.tsv

grep -v $'\t0/' out/nessus.tsv > out/nessus_ports.tsv
cat out/nessus_ports.tsv | cut -f1,4,5,7 | sed 's/\t/:/;s/\/\(tcp\|udp\)\t/\t/;s/www/http/;s/ssl/https/' | awk -F '\t' '{printf "%s://%s\t%s\n",$2,$1,$3}' | grep -v $'\t$' | sed 's/?:/:/;s#^http\(://[^:]*:443\)#https\1#' | sort -V > out/nessus_service_report.tsv

cat out/nessus.tsv | awk -F '\t' '{printf "%s\t%s\n",$7,$1}' | grep -v ^$'\t' | sort -Vu > out/nessus_issues.tsv
cat out/nessus_issues.tsv | sort -u | awk -F '\t' '{ a[$1] = a[$1] "\t" $2 } END { for (item in a ) print item, a[item] }' | sort -V | grep -v "^ " > out/nessus_issues_single.tsv
cat out/nessus_issues_single.tsv | grep -v "^#" | awk -F '\t' '{ for(i=1;i<=NF;i++) { print $i; } print '\n' }' > out/nessus_issue_layout.txt
cat out/nessus_issues_single.tsv | grep -v "^#" | awk -F '\t' '{printf "%s: %s resources affected\n",$1,NF-1}' | sed 's/\(: 1 resource\)s/\1/' > out/nessus_issue_count.txt

cat out/nessus.tsv | cut -f1,7 | grep -v $'\t$' | sort -uV > out/nessus_hosts.tsv
cat out/nessus_hosts.tsv | sort -Vu | awk -F '\t' '{ a[$1] = a[$1] "\t" $2 } END { for (item in a ) print item, a[item] }' | sort | grep -v "^ " > out/nessus_hosts_single.tsv
# host_count has some accidental OS included (incorrect tab use?)
cat out/nessus_hosts_single.tsv | grep -v "^#" | awk -F '\t' '{printf "%s: %s issues present\n",$1,NF-1}' | sed 's/\(: 1 resource\)s/\1/' > out/nessus_host_count.txt
cat out/nessus_hosts_single.tsv | grep -v "^#" | awk -F '\t' '{ for(i=1;i<=NF;i++) { print $i; } print '\n' }' > out/nessus_host_layout.txt

# Extract some useful results for immediate analysis
grep -e 'www' -e 'http' -e "${TAB}80/tcp" -e "${TAB}443/tcp" out/nessus.tsv | cut -f 1,4,5 | sed 's/www/http/;s/?//g;s#/tcp##' | awk -F'\t' '{print $3"://"$1":"$2}' | sed 's/^.*-http/http/;s/http\(s\)\?-[^:]*/http/' | sort -uV > out/web_servers.txt
grep -i -e default -e Unprivileged -e blank -e anonymous -e NULL -e guest -e Credential -e password out/nessus.tsv | grep -v -e uncredentialed -e 'Error' -e 'default file' | cut -f1,4,5,7 | sort -t\t -k3,3 > out/no_creds_required.txt

# Match lines with a CVE to the IP/PORT back to the MSF module, including exploit ranking, if it doesn't already exist
if [ ! -f "msf2cve.txt" ]
then
  echo "# Matching Hosts with CVE numbers to MSF Modules"
  grep -r "CVE[^-]" "$MSFDIR/modules" | grep -v '.svn' | sed 's/:[^0-9]*\([0-9-]*\).*/\tCVE-\1/;s#//#/#g' > msf2cve.txt
fi
cp msf2cve.txt out

OFS=$IFS
IFS=$'\n'
for i in $(cat "$VULN" | grep -o "CVE-[0-9]*-[0-9]*" | sort -Vru | grep -r -f - $OUTDIR/msf2cve.txt)
do 
  MSF=$(echo "$i" | cut -f1); 
  CVE=$(echo "$i" | cut -f2);
  HOSTP=$(cat "$VULN" | grep "$CVE" | cut -f1,4 | sed 's#/\(tcp\|udp\)##;s/\t/:/')
  for j in $(echo -e "$HOSTP")
  do
    RHOST=$(echo "$j" | cut -d':' -f1)
    RPORT=$(echo "$j" | cut -d':' -f2)
    echo "$MSFDIR/msfcli $MSF RHOST=\"$RHOST\" RPORT=\"$RPORT\" E"   
  done
done | sort -Vu > $OUTDIR/msfcli.txt
cat "$OUTDIR/msfcli.txt" | grep -v -e '/dos/' -e '/sqli' -e '/spoof/' -e '/scanner/' -e 'apache' > "$OUTDIR/msfcli_only_exploits.txt"
IFS=$OFS

# Aggregate common issues
# This aggregates them and combines hosts with each issue
mkdir out/findings
TAB=$'\t'
cat "$OUTDIR/nessus.tsv" | cut -f7,10 | grep -e "Critical" -e "High" -e "Medium" | cut -f1 | sort -u | cut -d' ' -f1 | sed 's/^MS[0-9-]*:/MS[0-9]/' | sort | uniq -c | sort -nr | sed 's/^ *//;s/ /\t/' | grep -v "^1$TAB" > "$OUTDIR/issue_aggregation.txt"
cut -f2 out/issue_aggregation.txt | grep -v "MS\[" | xargs -I{} ./aggregate_findings.sh {} # Keep Microsoft Findings Separate
./aggregate_findings.sh MicrosoftPatches 'MS[0-9]' # Process them if they exist
mkdir out/findings/data
mv out/combined_*  out/host_sanity_* out/findings/data
mv out/finding_* out/issues_* out/findings

echo "# Results are in out directory in txt and Tab Separated Format (tsv), import tsv files into Excel"
