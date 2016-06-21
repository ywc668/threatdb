#/bin/bash

#####
##### RST IP Reputation Database for Splunk Enterprise
##### Copyright (c) 2016 RST Cloud
##### https://www.rstcloud.net/
##### 
##### Author: Nikolay Arefiev
##### Contributor: Yury Sergeev
##### 

if [ -z "$1" ]; then
        echo 'Usage: start_threatupload.sh <threatdir>'
	echo ''
        exit
fi

threats_dir=$1
base_dir=/opt/splunk/bin/scripts/threatsDB
source_1='emergingthreats'
source_2='binarydefense'
source_3='alienvaultreputation'
source_4='sslipblacklist'
source_5='ransomwaretracker'
source_6='blocklistdessh'
source_7='blocklistdeapache'
source_8='blocklistdebots'
source_9='cinsscore'
source_10='sblam'

mkdir -p $threats_dir
rm -rf $threats_dir/*.feed

echo 'Start download'
echo

wget http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -O $threats_dir/$source_1.feed --no-check-certificate -N

wget http://www.binarydefense.com/banlist.txt -O $threats_dir/$source_2.feed --no-check-certificate -N

wget https://reputation.alienvault.com/reputation.snort.gz -P $threats_dir --no-check-certificate -N
gzip -d $threats_dir/reputation.snort.gz
mv $threats_dir/reputation.snort $threats_dir/$source_3.feed

wget https://sslbl.abuse.ch/blacklist/sslipblacklist.csv -O $threats_dir/$source_4.feed --no-check-certificate -N

wget https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt -O $threats_dir/$source_5.feed --no-check-certificate -N

wget https://lists.blocklist.de/lists/ssh.txt -O $threats_dir/$source_6.feed --no-check-certificate -N

wget https://lists.blocklist.de/lists/apache.txt -O $threats_dir/$source_7.feed --no-check-certificate -N

wget https://lists.blocklist.de/lists/bots.txt -O $threats_dir/$source_8.feed --no-check-certificate -N
 
wget http://cinsscore.com/list/ci-badguys.txt -O $threats_dir/$source_9.feed --no-check-certificate -N

wget http://sblam.com/blacklist.txt -O $threats_dir/$source_10.feed --no-check-certificate -N

echo 'Flush IP DB'
/usr/bin/python $base_dir/threat_flushdb.py netsdb flush

echo 'Start parsing and uploading'

echo
echo $source_1
/usr/bin/python $base_dir/threatuploader.py ipdb $source_1 $threats_dir/$source_1.feed

echo
echo $source_2
/usr/bin/python $base_dir/threatuploader.py ipdb $source_2 $threats_dir/$source_2.feed

echo
echo $source_3
/usr/bin/python $base_dir/threatuploader.py ipdb $source_3 $threats_dir/$source_3.feed

echo
echo $source_4
/usr/bin/python $base_dir/threatuploader.py ipdb $source_4 $threats_dir/$source_4.feed

echo
echo $source_5
/usr/bin/python $base_dir/threatuploader.py ipdb $source_5 $threats_dir/$source_5.feed

echo
echo $source_6
/usr/bin/python $base_dir/threatuploader.py ipdb $source_6 $threats_dir/$source_6.feed

echo
echo $source_7
/usr/bin/python $base_dir/threatuploader.py ipdb $source_7 $threats_dir/$source_7.feed

echo
echo $source_8
/usr/bin/python $base_dir/threatuploader.py ipdb $source_8 $threats_dir/$source_8.feed

echo
echo $source_9
/usr/bin/python $base_dir/threatuploader.py ipdb $source_9 $threats_dir/$source_9.feed

echo
echo $source_10
/usr/bin/python $base_dir/threatuploader.py ipdb $source_10 $threats_dir/$source_10.feed

exit 0
