# RST Cloud Threat Database Add-on for Splunk

## Goals

RST Cloud Threat Database Add-on allows to aggregate threat intelligence from multiple sources, store it locally in the Redis Database and quickly check a bunch of IP addresses against it. It makes possible to determine malicious IP addresses in the logs and use this information to analyse such activities.

The Threat Intelligence data will help you to:

* identify malicious activity in your infrastructure
* prioritise alerts based on IP reputation score
* classify attackers as blacklisted IPs, spam senders, web form spammers and so on
* determine fake search bots

Splunk add-on features:

* Automatically download IP reputation data and save in the Redis Database;
* Predefined macros helps to enrich your log containing IP addresses;
* A near real-time performance with an ability to process thousands of IPs at one time.

More information on: 

* https://rstcloud.net
* https://splunkbase.splunk.com/app/3236

## Prerequisites

* Install Redis (http://redis.io/) on Splunk Search Head (or other server) to store IP reputation data
* To run lookup command install some libraries on Splunk Search Head:

```
$ wget https://bootstrap.pypa.io/get-pip.py
$ python get-pip.py
$ sudo pip install redis 
$ sudo pip install netaddr
```

* All Python modules will be installed on your local Python instance, but not in Splunk Python instance
* Open $SPLUNK_HOME/etc/apps/threatDB/bin and edit this lines, if needed:

redisworker.py 
```
sys.path.append("/usr/local/lib/python2.7/dist-packages") # Path to redis-py module
redis_server = '127.0.0.1'
redis_port = 6379
```

threat_flushdb.py
```
redis_server = '127.0.0.1'
redis_port = 6379
```

threatuploader.py
```
redis_server = '127.0.0.1'
redis_port = 6379
```

start_threatupload.sh
```
base_dir=/opt/splunk/bin/scripts/threatDB
python_bindir=/usr/bin
```

* Database must be accessed from Splunk Search Head 

## Getting Started

* Create the directory to store feeds:

```
$ mkdir -p /tmp/threatsupload
```

* Modify /etc/crontab to create an update job (update once peer day, in database entry TTL = 48 hours):

```
2 0 * * * root $SPLUNK_HOME/etc/apps/threatDB/bin/start_threatupload.sh /tmp/threatsupload
```
root is an example here. In production environment you can use any user account.


## Usage

* To start on Search app:
 
```
| lookup local=true lookupthreat clientip
```
local - needed to start scripts only on Splunk Head Search, but not on Indexers

* To parse script output you can use the macros:

```
| `threatDB(clientip)`
```

## License
RST Cloud Threat Database is released under the [MIT License](MIT-LICENSE) by RST Cloud (https://www.rstcloud.net)
