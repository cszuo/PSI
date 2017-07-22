from gevent.pool import Pool
from gevent import monkey; monkey.patch_all()

import inspection
import portscanner


spool = None

def identified(ip, port, service):
    print ip, port, service
    with open('services.txt', 'a+') as outfile:
        outfile.write('%s:%s:%s\n' % (ip,port,service))

def sscan(ip, port):
    global spool
    spool.spawn(inspection.recogn,ip, port, callback=identified)  
    with open('openports.txt', 'a+') as outfile:
        outfile.write('%s:%s\n' % (ip,port))  

def scan(sip, eip, ports=[], spoolsize=100, ppoolsize=100, t_c=5):
    global spool
    spool = Pool(spoolsize)

    portscanner.scan(sip, eip, ports=ports, poolsize=ppoolsize, callback=sscan, t_c=t_c)

    spool.join()

scan('138.68.228.0', '138.68.228.254', ports=range(1,100), spoolsize=100, ppoolsize=100, t_c=5)