from gevent import Timeout
from gevent.pool import Pool
from gevent import monkey; monkey.patch_all()

import socket
import ssl
import struct

timeout_connect = None

def isopen(ip, port, callback):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with Timeout(timeout_connect):
            sock.connect((ip, int(port)))
        callback(ip, port)
    except :
        pass
    finally:
        try:
            sock.close()
        except:
            pass
    return True

def ip2int(addr):                                                               
    return struct.unpack("!I", socket.inet_aton(addr))[0]  

def int2ip(addr):                                                               
    return socket.inet_ntoa(struct.pack("!I", addr))                            

def scan(sip, eip, ports=[], sp=0, ep=-1, poolsize=10, callback=None, t_c=5):
    global timeout_connect
    timeout_connect = t_c

    result = []

    sip = ip2int(sip)
    eip = ip2int(eip)
    
    if len(ports) == 0:
        ports = range(sp, ep+1)
    
    if eip < sip or len(ports) == 0: return result

    def yes(ip,port):
        result.append((ip,port))
        if callback!= None: callback(ip,port)
        #print (ip,port)

    pool = Pool(poolsize)

    for ip in range(sip, eip+1):
        ip = int2ip(ip)
        for port in ports:
            #print ip, port
            pool.spawn(isopen, ip, port, yes)
    pool.join()
    return result

'''
def cb(ip,port):
    print ip,port

scan('138.68.228.0', '138.68.228.254', sp=22, ep=80, callback=cb, poolsize=100)
'''




