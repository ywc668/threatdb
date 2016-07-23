#!/usr/bin/python

#####
##### RST Threat Database add-on for Splunk Enterprise
##### Copyright (c) 2016 RST Cloud
##### https://www.rstcloud.net/
##### 
##### Author: Nikolay Arefiev
##### Contributor: Yury Sergeev
##### 

import sys
import redis
from netaddr import *

if len(sys.argv) != 4:
    print "Usage: python threatuploader.py (ipdb|domaindb) filetype filepath"
    print "available filetypes: emergingthreats, binarydefense, alienvaultreputation, sslipblacklist, ransomwaretracker, blocklistdessh, blocklistdeapache, blocklistdebots, cinsscore, sblam, stopforumspam"
    sys.exit(0)

db_type = sys.argv[1]
threatfile_type = sys.argv[2]
threatfile_path = sys.argv[3]

redis_server = '127.0.0.1'
redis_port = 6379
redis_ipdb = 0
redis_domaindb=1

# TTL of entry in the database
threat_ttl=172800 # 48 hours

def threatscore_calc(threttype):
    out=0
    # AlienVailt DB threat types
    if threttype == 'Malicious Host':
        out=20
    if threttype == 'Scanning Host':
        out=5
    if threttype == 'Spamming Host':
        out=10
    return str(out) 

# Upload parsed data to Redis
# rpipe - redis-py pipeline object
# ltype - 'ip'|'net'
# lobj - ip address| CIDR
# thsource - threat source
# thtype - threat category
# thscore - threat score
# thttl - TTL of key in Redis
def upload2redis(rpipe, ltype, lobj, thsource, thtype, thscore, thttl):
    try:
        # Add the key to redis (ip|net:IPaddress|CIDR) => List [ThreatSource1:score1, ThreatSource2:score1] 
        rpipe.sadd(ltype+':'+lobj, "%s:%s:%s" % (thsource, thtype, str(thscore))).expire(ltype+':'+lobj,thttl)
        # Add to index 'net:index'=> Set [CIDR]
        if ltype == 'net':
            rpipe.sadd('net:index',lobj)
    except:
        print 'status=error, message="Cant insert data to Redis"'
        sys.exit(1)
        
def parse_emergingthreats(file_path, red):
    threatscore = 10
    threattype = 'Compromised IP'
    
    red_pipe = red.pipeline()
    iplist_object = open(file_path, "r")
    current_threatsource=''
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '':
            continue
        # Parse Feodo
        if line == '# Feodo':
            current_threatsource = 'Feodo'
            continue
        if line == '# Zeus':
            current_threatsource = 'Zeus'
            continue
        if line == '# Spyeye':
            current_threatsource = 'Spyeye'
            continue
        if line == '# Palevo':
            current_threatsource = 'Palevo'
            continue
        if line == '#Spamhaus DROP Nets':
            current_threatsource = 'Spamhaus DROP Nets'
            continue
        if line == '#Dshield Top Attackers':
            current_threatsource = 'Dshield Top Attackers'
            continue            
        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 
            
        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)

    red_pipe.execute()
    iplist_object.close()
    
def parse_binarydefense(file_path, red):
    threatscore = 10
    threattype = 'Compromised IP'
    
    red_pipe = red.pipeline() 
    iplist_object = open(file_path, "r")    
    current_threatsource='Binary Defense'
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '' or line[0] == '#':
            continue
        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 

        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)
    
    red_pipe.execute()
    iplist_object.close()
    
def parse_alienvaultreputation(file_path, red):
    threattype = ''
    
    red_pipe = red.pipeline()
    iplist_object = open(file_path, "r")    
    current_threatsource='AlienVault'
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '' or line[0] == '#':
            continue
        linetemp = line.split('#', 1)
        line = linetemp[0].strip()
        threattype = linetemp[1].split(';',1)[0].strip()
        threatscore = threatscore_calc(threattype)
        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 
        
        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)
    
    red_pipe.execute()
    iplist_object.close()
    
def parse_sslipblacklist(file_path, red):
    threatscore = 5
    threattype = ''
    
    red_pipe = red.pipeline()     
    iplist_object = open(file_path, "r")    
    current_threatsource='SSL Black list'
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '' or line[0] == '#':
            continue
        linetemp = line.split(',')
        line = linetemp[0].strip()
        threattype = linetemp[2].strip()

        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 

        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)
    
    red_pipe.execute()
    iplist_object.close()

def parse_ransomwaretracker(file_path, red):
    threatscore = 10
    threattype = 'Compromised IP'
    
    red_pipe = red.pipeline()
    iplist_object = open(file_path, "r")    
    current_threatsource='RansomWare'
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '' or line[0] == '#':
            continue
        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 

        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)
    
    red_pipe.execute()
    iplist_object.close()

def parse_blocklistde(file_path, red, threatscore, threattype):
    red_pipe = red.pipeline()
    
    iplist_object = open(file_path, "r")    
    current_threatsource='BlocklistDE'
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '' or line[0] == '#':
            continue
        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 

        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)
    
    red_pipe.execute()
    iplist_object.close()
    
def parse_blocklistde_ssh(fp, rd):
    parse_blocklistde(fp, rd, 20, 'SSH attacks')
    
def parse_blocklistde_apache(fp, rd):
    parse_blocklistde(fp, rd, 10, 'Apache attacks')

def parse_blocklistde_bots(fp, rd):
    parse_blocklistde(fp, rd, 10, 'Bad bots')

def parse_cinsscore(file_path, red):
    threatscore = 10
    threattype = 'Compromised IP'
    red_pipe = red.pipeline()
    
    iplist_object = open(file_path, "r")    
    current_threatsource='CINSScore'
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '' or line[0] == '#':
            continue
        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 

        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)
    
    red_pipe.execute()
    iplist_object.close()

def parse_sblam(file_path, red):
    threatscore = 5
    threattype = 'Web Form Spammer IP'
    red_pipe = red.pipeline()
    
    iplist_object = open(file_path, "r")    
    current_threatsource='Sblam'
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '' or line[0] == '#':
            continue
        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 

        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)
    
    red_pipe.execute()
    iplist_object.close()
    
def parse_stopforumspam(file_path, red):
    threatscore = 5
    threattype = 'Web Form Spammer IP'
    red_pipe = red.pipeline()
    
    iplist_object = open(file_path, "r")    
    current_threatsource='StopForumSpam'
    for row in iplist_object:
        line_type=''
        line = row[:-1]
        if line == '' or line[0] == '#':
            continue
        try:    
            IPAddress(line)
            line_type='ip'
        except AddrFormatError:
            continue
        except ValueError:
            try:
                IPNetwork(line)
                line_type='net'
            except AddrFormatError:
                continue
            except ValueError:
                continue 

        upload2redis(red_pipe, line_type, line, current_threatsource, threattype, threatscore, threat_ttl)
    
    red_pipe.execute()
    iplist_object.close()
    
def make_redisconn(conn_db):
    try:
        redis_pool = redis.ConnectionPool(host=redis_server, port=redis_port, db=conn_db)
        redis_conn = redis.Redis(connection_pool=redis_pool)
	redis_conn.ping()
    except:
        print 'status=error, message="Redis connection error '+redis_server+':'+str(redis_port)+'"'
        sys.exit(0)
    return redis_conn

def main():
    if db_type == 'ipdb':
        red = make_redisconn(redis_ipdb)

        if threatfile_type == 'emergingthreats':
            parse_emergingthreats(threatfile_path, red)
        if threatfile_type == 'binarydefense':
            parse_binarydefense(threatfile_path, red)
        if threatfile_type == 'alienvaultreputation':
            parse_alienvaultreputation(threatfile_path, red)
        if threatfile_type == 'sslipblacklist':
            parse_sslipblacklist(threatfile_path, red)
        if threatfile_type == 'ransomwaretracker':
            parse_ransomwaretracker(threatfile_path, red)
        if threatfile_type == 'blocklistdessh':
            parse_blocklistde_ssh(threatfile_path, red)
        if threatfile_type == 'blocklistdeapache':
            parse_blocklistde_apache(threatfile_path, red)
        if threatfile_type == 'blocklistdebots':
            parse_blocklistde_bots(threatfile_path, red)
        if threatfile_type == 'cinsscore':
            parse_cinsscore(threatfile_path, red)
        if threatfile_type == 'sblam':
            parse_sblam(threatfile_path, red)
        if threatfile_type == 'stopforumspam':
            parse_stopforumspam(threatfile_path, red)
            
        print 'status=done, threatsource='+threatfile_type

    if db_type == 'domaindb':
        print 'status=error, message="domaindb is not implemented yet"'

main()
sys.exit(0)
