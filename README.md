# threatdb

RST IP Reputation Database for Splunk Enterprise

## Goals

- fetch and merge threat intelligence data from different sources
- fast access IP Reputation data from Splunk

## Prerequisites

1. Install Redis (http://redis.io/) on Splunk Search Head (or other server) to store IP reputation data
2. To run redisworker.py install some libraries on Splunk Search Head:
```
$ wget https://bootstrap.pypa.io/get-pip.py
$ python get-pip.py
$ sudo pip install redis 
$ sudo pip install netaddr
```
3. All Python modules will be installed on your local python, but not in splunk pyhon instance
4. Open redisworker.py and edit this lines, if needed
```
sys.path.append("/usr/local/lib/python2.7/dist-packages")
redis_server = '127.0.0.1'
redis_port = 6379
```
5. Database must be accessed from Splunk Searc Head 

## Getting Started

1. Copy redisworker.py, threat_flushdb.py, threatuploader.py, start_threatupload.sh to the following directories:

```
$ cp redisworker.py $SPLUNK_HOME/etc/apps/search/bin/redisworker.py
$ mkdir $SPLUNK_HOME/bin/scripts/threatDB/
$ cp threat* $SPLUNK_HOME/bin/scripts/threatDB/
```

2. Create directory to store feeds:

```
$ mkdir -p /tmp/threatsupload
```

3. Modify /etc/crontab to create an update job:

```
2 0 * * * root /opt/splunk/bin/scripts/threatsDB/start_threatupload.sh /tmp/threatsupload
```
root is an example here. In production environment you can use any user account.

4. Create a lookup in Splunk UI - Lookup definitions - Search app:
* Name lookupthreat
* Command: redisworker.py clientip threatscore
* Fields: clientip threatsource threatcategory threatscore

5. Add permissions for lookup to share between Splunk apps

## Usage

1. To start on Search app:
 
```
search * | tail 5 |local| lookup local=true lookupthreat clientip
```
local - needed for start scripts only on Splunk Head Search, but not on Indexers

2. For parse script output you can use macros

```
Name: threatDB(1)
Definition: lookup local=true lookupthreat $arg1$|eval threatcategory=split(threatcategory, ","), threatsource=split(threatsource, ","),threatscore=split(threatscore, ",")| eventstats sum(threatscore) as sumthreatscore by $arg1$|eval threatscore=sumthreatscore |fields - sumthreatscore
Arguments: arg1
```

Like this:
```
search * | tail 5 |local| `threatDB(clientip)`
```

## License
threatdb is released under the [MIT License](MIT-LICENSE) by RST Cloud (https://www.rstcloud.net)
