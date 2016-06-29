# threatdb

RST IP Reputation Database for Splunk Enterprise

## Goals

- fetch and merge threat intelligence data from different sources
- fast access IP Reputation data from Splunk

## Prerequisites
Install redis (http://redis.io/) to store IP reputation data
Database must be accessed by redisworker.py script

To run redisworker.py install some libraries:
```
$ wget https://bootstrap.pypa.io/get-pip.py
$ python get-pip.py
$ sudo pip install redis 
$ sudo pip install netaddr
```

## Getting Started

Copy redisworker.py, threat_flushdb.py, threatuploader.py, start_threatupload.sh to the following directories:

```
$ cp redisworker.py $SPLUNK_HOME/etc/apps/search/bin/redisworker.py
$ cp threat* $SPLUNK_HOME/bin/scripts/threatDB/
```

Modify /etc/crontab to create an update job:

```
2 0 * * * root /opt/splunk/bin/scripts/threatsDB/start_threatupload.sh /tmp/threatsupload
```
root is an example here. In production environment you can use any user account.

Create a lookup in Splunk UI - Lookup definitions - Search app:
* Name lookupthreat
* Command: redisworker.py clientip threatscore
* Fields: clientip threatsource threatcategory threatscore


## Usage


```
search * | tail 5 | lookup lookupthreat clientip
```


## License
threatdb is released under the [MIT License](MIT-LICENSE) by RST Cloud (https://www.rstcloud.net)
