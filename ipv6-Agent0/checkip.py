#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'moonshawdo@gamil.com'
"""
修改：SeaHOH
验证哪些 IP 可以用在 gogagent 中
主要是检查这个ip是否可以连通，并且检查服务端是否为 gws
"""

import os
import sys
import threading
import socket
import ssl
import re
import select
import traceback
import logging
import random

#最大IP延时，单位毫秒
g_maxhandletimeout = 1500
#需要得到的可用IP数量
g_maxhandleipcnt = 1000
#每轮扫描的IP数量
g_maxthreads = 100

#连接超时设置，单位秒
g_conntimeout = 3
g_handshaketimeout = 5
#SSL 连接：0使用 OpenSSL，1使用 gevent
g_usegevent = 1

g_filedir = os.path.dirname(__file__)
g_cacertfile = os.path.join(g_filedir, "cacert.pem")
g_ipfile = os.path.join(g_filedir, "ip.txt")
g_tmpnotfile = os.path.join(g_filedir, "ip_not.txt")
g_tmpokfile = os.path.join(g_filedir, "ip_ok.txt")
g_tmperrorfile = os.path.join(g_filedir, "ip_error.txt")
g_exttraipfile = os.path.join(g_filedir,"G.ip.txt")

#是否自动删除文件，0不删除，1删除
#记录查询成功的非google的IP
#文件名：ip_not.txt，格式：ip 连接与握手时间 ssl域名
g_autodeltmpnotfile = 1
#记录查询成功的google的IP
#文件名：ip_ok.txt，格式：ip 连接与握手时间 ssl域名
g_autodeltmpokfile = 1
#记录查询失败的IP
#ip_error.txt，格式：ip
g_autodeltmperrorfile = 1

"""
ip_str_list为需要查找的IP地址，第一组的格式：
1.xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx
2.xxx.xxx.xxx.xxx/xx
3.xxx.xxx.xxx.
4 xxx.xxx.xxx.xxx
5 xxx.xxx.xxx.xxx-xxx

组与组之间可以用换行相隔开,第一行中IP段可以用'|'或','
获取随机IP是每组依次获取随机个数量的，因此一组的IP数越少，越有机会会检查，当然获取随机IP会先排除上次查询失败的IP
"""
ip_str_list = '''
'''

PY3 = False
if sys.version_info[0] == 3:
    from queue import Queue, Empty
    PY3 = True
    try:
        from functools import reduce
    finally:
        pass
    try:
        xrange
    except NameError:
        xrange = range
else:
    from Queue import Queue, Empty
import time
from time import sleep
 
g_useOpenSSL = 1
if g_usegevent == 1:
    try:
        from gevent import monkey
        monkey.patch_all(Event=True)
        g_useOpenSSL = 0
        from gevent import sleep
    except ImportError:
        g_usegevent = 0

if g_useOpenSSL == 1:
    try:
        import OpenSSL.SSL

        SSLError = OpenSSL.SSL.WantReadError
        g_usegevent = 0
    except ImportError:
        g_useOpenSSL = 0
        SSLError = ssl.SSLError
else:
    SSLError = ssl.SSLError

# gevent socket cnt must less than 1024
if g_usegevent == 1 and g_maxthreads > 1000:
    g_maxthreads = 128

#g_ssldomain = ("google.com",)
g_ssldomain = ()
g_excludessdomain=()


logging.basicConfig(format="[%(threadName)s]%(message)s",level=logging.INFO)


evt_ipramdomstart = threading.Event()
evt_ipramdomend = threading.Event()

def PRINT(strlog):
    logging.info(strlog)
    
def isgoolgledomain(domain):
    lowerdomain = domain.lower()
    if lowerdomain in g_ssldomain:
        return 1
    if lowerdomain in g_excludessdomain:
        return 0
    return 2

def isgoogleserver(svrname):
    lowerdomain = svrname.lower()
    if lowerdomain == "gws":
        return True
    else:
        return False

def checkvalidssldomain(domain,svrname):
    ret = isgoolgledomain(domain)
    if ret == 1:
        return True
    elif ret == 0:
        return False
    elif len(svrname) > 0 and isgoogleserver(svrname):
        return True
    else:
        return False

prekey="\nServer:"
def getgooglesvrnamefromheader(header):
    begin = header.find(prekey)
    if begin != -1: 
        begin += len(prekey)
        end = header.find("\n",begin)
        if end == -1:
            end = len(header)
        gws = header[begin:end].strip(" \t")
        return gws
    return ""

class TCacheResult(object):
    __slots__ = ["oklist","failiplist","notlock","oklock","errlock","notfile","okfile","errorfile","validipcnt"]
    def __init__(self):
        self.oklist = list()
        self.failiplist = list()
        self.notlock = threading.Lock()
        self.oklock = threading.Lock()
        self.errlock = threading.Lock()
        self.notfile = None
        self.okfile = None
        self.errorfile = None
        self.validipcnt = 0
    
    def addOKIP(self,costtime,ip,ssldomain,gwsname):
        bOK = False
        if checkvalidssldomain(ssldomain,gwsname):
            bOK = True
            self.oklist.append((costtime,ip,ssldomain,gwsname))
            try:
                self.oklock.acquire()
                if self.okfile is None:
                    self.okfile = open(g_tmpokfile,"a+",0)
                self.okfile.seek(0,2)
                line = "%s %d %s %s\n" % (ip, costtime, ssldomain,gwsname)
                self.okfile.write(line)
                if bOK and costtime <= g_maxhandletimeout:
                    self.validipcnt += 1
                    return 1,self.validipcnt
                else:
                    return 0,self.validipcnt
            finally:
                self.oklock.release()
        else:
            try:
                self.notlock.acquire()
                if self.notfile is None:
                    self.notfile = open(g_tmpnotfile,"a+",0)
                self.notfile.seek(0,2)
                line = "%s %d %s %s\n" % (ip, costtime, ssldomain,gwsname)
                self.notfile.write(line)
                return 0,self.validipcnt
            finally:
                self.notlock.release()
            
    def addFailIP(self,ip):
        try:
            self.errlock.acquire()
            if self.errorfile is None:
                self.errorfile = open(g_tmperrorfile,"a+",0)
            self.errorfile.seek(0,2)
            self.errorfile.write(ip+"\n")
            self.failiplist.append(ip)
            if len(self.failiplist) > 128:
                self.flushFailIP()
        finally:
            self.errlock.release() 
    
    def close(self):
        if self.notfile:
            self.notfile.close()
            self.notfile = None
        if self.okfile:
            self.okfile.close()
            self.okfile = None
        if self.errorfile:
            self.errorfile.close()
            self.errorfile = None
       
    def getIPResult(self):
        return self.oklist
    
    def flushFailIP(self):
        nLen = len(self.failiplist)
        if nLen > 0 :
            self.failiplist = list()
            PRINT("=====================================================================")
            PRINT( u"                             %d IP 超时" % nLen )


    def loadLastResult(self):
        notresult  = set()
        okresult  = set()
        errorresult = set()
        if os.path.exists(g_tmpnotfile):
            with open(g_tmpnotfile,"r") as fd:
                for line in fd:
                    ips = line.strip("\r\n").split(" ")
                    notresult.add(from_string(ips[0]))
        if os.path.exists(g_tmpokfile):
            with open(g_tmpokfile,"r") as fd:
                for line in fd:
                    ips = line.strip("\r\n").split(" ")
                    okresult.add(from_string(ips[0]))
                    gwsname = ""
                    costtime = int(ips[1])
                    if len(ips) > 3:
                        gwsname = ips[3]
                    self.oklist.append((costtime,ips[0],ips[2],gwsname))
                    if costtime <= g_maxhandletimeout:
                        self.validipcnt += 1
        if os.path.exists(g_tmperrorfile):
            with open(g_tmperrorfile,"r") as fd:
                for line in fd:
                    ips = line.strip("\r\n").split(" ")
                    for item in ips:
                        errorresult.add(from_string(item))
        return notresult,okresult,errorresult
    
    def clearFile(self):
        self.close()
        if g_autodeltmpnotfile and os.path.exists(g_tmpnotfile):
            os.remove(g_tmpnotfile)
            PRINT(u"删除文件 %s" % g_tmpnotfile)
        if g_autodeltmpokfile and os.path.exists(g_tmpokfile):
            os.remove(g_tmpokfile)
            PRINT(u"删除文件 %s" % g_tmpokfile)
        if g_autodeltmperrorfile and os.path.exists(g_tmperrorfile):
            os.remove(g_tmperrorfile)
            PRINT(u"删除文件 %s" % g_tmperrorfile)
            
    def queryfinish(self):
        try:
            self.oklock.acquire()
            return self.validipcnt >= g_maxhandleipcnt
        finally:
            self.oklock.release()

class my_ssl_wrap(object):
    ssl_cxt = None
    ssl_cxt_lock = threading.Lock()
    httpreq = "GET / HTTP/1.1\r\nAccept: */*\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n"

    def __init__(self):
        pass

    @staticmethod
    def initsslcxt():
        if my_ssl_wrap.ssl_cxt is not None:
            return
        try:
            my_ssl_wrap.ssl_cxt_lock.acquire()
            if my_ssl_wrap.ssl_cxt is not None:
                return
            my_ssl_wrap.ssl_cxt = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            my_ssl_wrap.ssl_cxt.set_timeout(g_handshaketimeout)
            PRINT(u"ssl 环境初始化完毕")
        except Exception:
            raise
        finally:
            my_ssl_wrap.ssl_cxt_lock.release()

    def getssldomain(self, threadname, ip):
        time_begin = time.time()
        s = None
        c = None
        haserror = 1
        timeout = 0
        domain = None
        gwsname = ""
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if g_useOpenSSL:
                my_ssl_wrap.initsslcxt()
                s.settimeout(g_conntimeout)
                s.connect((ip, 443))
                c = OpenSSL.SSL.Connection(my_ssl_wrap.ssl_cxt, s)
                c.set_connect_state()
                s.setblocking(0)
                while True:
                    try:
                        c.do_handshake()
                        break
                    except SSLError:
                        infds, outfds, errfds = select.select([s, ], [], [], g_handshaketimeout)
                        if len(infds) == 0:
                            raise SSLError("do_handshake timed out")
                        else:
                            costtime = int(time.time() - time_begin)
                            if costtime > g_handshaketimeout:
                                raise SSLError("do_handshake timed out")
                            else:
                                pass
                    except OpenSSL.SSL.SysCallError as e:
                        raise SSLError(e.args)
                time_end = time.time()
                cert = c.get_peer_certificate()
                costtime = int(time_end * 1000 - time_begin * 1000)
                for subject in cert.get_subject().get_components():
                    if subject[0] == "CN":
                        domain = subject[1]
                        haserror = 0
                if domain is None:
                    PRINT(u"%s 无法获取 CN：%s " % (ip, cert.get_subject().get_components()))
                #尝试发送http请求，获取回应头部的Server字段
                if domain is None or isgoolgledomain(domain) == 2:
                    cur_time = time.time()
                    gwsname = self.getgooglesvrname(c,s,ip)
                    time_end = time.time()
                    costtime += int(time_end * 1000 - cur_time * 1000)
                    if domain is None and len(gwsname) > 0:
                        domain="defaultgws"
                return domain, costtime,timeout,gwsname
            else:
                s.settimeout(g_conntimeout)
                c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs=g_cacertfile,
                                    do_handshake_on_connect=False)
                c.settimeout(g_conntimeout)
                c.connect((ip, 443))
                c.settimeout(g_handshaketimeout)
                c.do_handshake()
                time_end = time.time()
                cert = c.getpeercert()
                costtime = int(time_end * 1000 - time_begin * 1000)
                if 'subject' in cert:
                    subjectitems = cert['subject']
                    for mysets in subjectitems:
                        for item in mysets:
                            if item[0] == "commonName":
                                if not isinstance(item[1], str):
                                    domain = item[1].encode("utf-8")
                                else:
                                    domain = item[1]
                                haserror = 0
                    if domain is None:
                        PRINT(u"%s 无法获取 commonName：%s " % (ip, subjectitems))
                #尝试发送http请求，获取回应头部的Server字段
                if domain is None or isgoolgledomain(domain) == 2:
                    cur_time = time.time()
                    gwsname = self.getgooglesvrname(c,s,ip)
                    time_end = time.time()
                    costtime += int(time_end * 1000 - cur_time * 1000)
                    if domain is None and len(gwsname) > 0:
                        domain="defaultgws"
                return domain, costtime,timeout,gwsname
        except SSLError as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            if str(e).endswith("timed out"):
                timeout = 1
            else:
                PRINT(u"SSL Exception(%s)：%s，耗时：%d ms " % (ip, e, costtime))
            return domain, costtime,timeout,gwsname
        except IOError as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            if str(e).endswith("timed out"):
                timeout = 1
            else:
                PRINT(u"Catch IO Exception(%s)：%s 耗时：%d ms " % (ip, str(e).decode("gbk"), costtime))
            return domain, costtime,timeout,gwsname
        except Exception as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            PRINT(u"Catch Exception(%s)：%s 耗时：%d ms " % (ip, str(e).decode("gbk"), costtime))
            return domain, costtime,timeout,gwsname
        finally:
            if g_useOpenSSL:
                if c:
                    if haserror == 0:
                        c.shutdown()
                        c.sock_shutdown(2)
                    c.close()
                if s:
                    s.close()
            else:
                if c:
                    if haserror == 0:
                        c.shutdown(2)
                    c.close()
                elif s:
                    s.close()
                    
    def getgooglesvrname(self,conn,sock,ip):
        try:
            myreq = my_ssl_wrap.httpreq % ip
            conn.write(myreq)
            data=""
            sock.setblocking(0)
            trycnt = 0
            begin = time.time()
            conntimeout = g_conntimeout if g_usegevent == 0 else 0.001
            while True:
                end = time.time()
                costime = int(end-begin)
                if costime >= g_conntimeout:
                    PRINT(u"获取 http 响应超时(%ss)，ip：%s，数量：%d" % (costime,ip,trycnt) )
                    return ""
                trycnt += 1
                infds, outfds, errfds = select.select([sock, ], [], [], conntimeout)
                if len(infds) == 0:
                    if g_usegevent == 1:
                        sleep(0.5)
                    continue
                timeout = 0
                try:
                    d = conn.read(1024)
                except SSLError as e:
                    sleep(0.5)
                    continue
                readlen = len(d)
                if readlen == 0:
                    sleep(0.5)
                    continue
                data = data + d.replace("\r","")
                index = data.find("\n\n")
                if index != -1:
                    gwsname = getgooglesvrnamefromheader(data[0:index])
                    return gwsname
                elif readlen <= 64:
                    sleep(0.01)
            return ""
        except Exception as e:
            info = "%s" % e
            if len(info) == 0:
                info = type(e)
            PRINT("Catch Exception(%s) in getgooglesvrname: %s" % (ip, info))
            return ""


class Ping(threading.Thread):
    ncount = 0
    ncount_lock = threading.Lock()
    __slots__=["checkqueue","cacheResult"]
    def __init__(self,checkqueue,cacheResult):
        threading.Thread.__init__(self)
        self.queue = checkqueue
        self.cacheResult = cacheResult

    def runJob(self):
        while not evt_ipramdomstart.is_set():
            evt_ipramdomstart.wait(5)
        while not self.cacheResult.queryfinish():
            try:
                if self.queue.qsize() == 0 and evt_ipramdomend.is_set():
                    break
                addrint = self.queue.get(True,2)
                ipaddr = to_string(addrint)
                self.queue.task_done()
                ssl_obj = my_ssl_wrap()
                (ssldomain,costtime,timeout,gwsname) = ssl_obj.getssldomain(self.getName(), ipaddr)
                if ssldomain is not None:
                    ok,cnt = self.cacheResult.addOKIP(costtime, ipaddr, ssldomain,gwsname)
                    PRINT(u"延迟：%s %s %s 服务端：%s 可用：%s 数量：%d" % (costtime,ipaddr,ssldomain,gwsname,ok,cnt))
                elif ssldomain is None:
                    self.cacheResult.addFailIP(ipaddr)
            except Empty:
                pass

    def run(self):
        try:
            Ping.ncount_lock.acquire()
            Ping.ncount += 1
            Ping.ncount_lock.release()
            self.runJob()
        except Exception:
            raise
        finally:
            Ping.ncount_lock.acquire()
            Ping.ncount -= 1
            Ping.ncount_lock.release()
    
    @staticmethod 
    def getCount():
        try:
            Ping.ncount_lock.acquire()
            return Ping.ncount
        finally:
            Ping.ncount_lock.release()
            
            
class RamdomIP(threading.Thread):
    def __init__(self,checkqueue,cacheResult):
        threading.Thread.__init__(self)
        self.ipqueue = checkqueue
        self.cacheResult = cacheResult
        self.hadaddipcnt = 0
        
    def ramdomip(self):
        lastnotresult,lastokresult,lasterrorresult = self.cacheResult.loadLastResult()
        notlen = len(lastnotresult)
        oklen = len(lastokresult)
        errorlen = len(lasterrorresult)
        totalcachelen = notlen + oklen + errorlen
        if totalcachelen != 0:
            PRINT(u"载入上次结果完毕。可用数：%d，不可用数：%d，错误数：%d" % (oklen,notlen,errorlen) )
        iplineslist = re.split("\r|\n", ip_str_list)
        iplinelist = []
        cacheip = lastnotresult | lastokresult | lasterrorresult
        if os.path.exists(g_exttraipfile):
            try:
                fp = open(g_exttraipfile,"r")
                linecnt = 0
                for line in fp:
                    iplineslist.append(line.strip("\r\n"))
                    linecnt += 1
                fp.close()
                PRINT(u"载入自定义 IP 完毕。行数：%d" % linecnt )
            except Exception as e:
                PRINT(u"载入自定义 IP 错误：%s " % str(e) )
        for iplines in iplineslist:
            if len(iplines) == 0 or iplines[0] == '#':
                continue
            singlelist = []
            ips = re.split(",|\|", iplines)
            for line in ips:
                if len(line) == 0 or line[0] == '#':
                    continue
                begin, end = splitip(line)
                if checkipvalid(begin) == 0 or checkipvalid(end) == 0:
                    PRINT(u"ip 格式错误，行：%s，起始：%s，结束：%s" % (line, begin, end))
                    continue
                nbegin = from_string(begin)
                nend = from_string(end)
                iplinelist.append([nbegin,nend])
        
        hadIPData = True
        putdata = False
        while hadIPData:
            if evt_ipramdomend.is_set():
                break
            hadIPData = False
            index = -1
            emptyindexlist=[]
            #PRINT("ramdom ip array: % d" % len(iplinelist))
            for itemlist in iplinelist:
                begin = itemlist[0]
                end = itemlist[1]
                itemlen = end - begin + 1
                index += 1
                if itemlen <= 0:
                    continue
                if self.cacheResult.queryfinish():
                    break
                if itemlen > 1000:
                    selectcnt = 5
                elif itemlen <= 2:
                    selectcnt = itemlen
                else:
                    selectcnt = 2
                for i in xrange(0,selectcnt):
                    k = random.randint(begin,end)
                    first = True
                    findOK = True
                    checkcnt = 0
                    checkend = k
                    # try get next index in circle
                    while k in cacheip:
                        checkcnt += 1
                        if k < end:
                            k += 1
                        else:
                            k = begin
                        # if met itself,nee break
                        if k == checkend :
                            findOK = False
                            break
                    #if checkcnt > 1:
                    #    PRINT("[%d]total cnt: %d,index:%d,ramdom checkcnt:%d,found:%d" % (index,itemlen,checkend-begin,checkcnt,findOK))
                    if findOK:
                        hadIPData = True
                        self.ipqueue.put(k)
                        cacheip.add(k)
                        self.hadaddipcnt += 1
                        if not putdata:
                            evt_ipramdomstart.set()
                            putdata = True
                    if evt_ipramdomend.is_set():
                        break
                    # not found,no need to ramdom next index
                    if not findOK:
                        emptyindexlist.insert(0,index)
                        break
            if self.ipqueue.qsize() >= 500:
                sleep(1)
            for empytindex in emptyindexlist:
                iplinelist.pop(empytindex)
                #PRINT("remote index: %d" % empytindex )
        if not evt_ipramdomstart.is_set():
            evt_ipramdomstart.set()
        
    def run(self):
        PRINT(u"开始获取随机 IP")
        self.ramdomip()
        evt_ipramdomend.set()
        qsize = self.ipqueue.qsize()
        PRINT(u"随机 IP 线程已结束。已检查 IP 数：%d，剩余 IP 数：%d" % (self.hadaddipcnt - qsize,qsize))
        PRINT("====================================================================")

def from_string(s):
    """Convert dotted IPv4 address to integer."""
    return reduce(lambda a, b: a << 8 | b, map(int, s.split(".")))


def to_string(ip):
    """Convert 32-bit integer to dotted IPv4 address."""
    return ".".join(map(lambda n: str(ip >> n & 0xFF), [24, 16, 8, 0]))


g_ipcheck = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def checkipvalid(ip):
    """检查ipv4地址的合法性"""
    ret = g_ipcheck.match(ip)
    if ret is not None:
        "each item range: [0,255]"
        for item in ret.groups():
            if int(item) > 255:
                return 0
        return 1
    else:
        return 0


def splitip(strline):
    """从每组地址中分离出起始IP以及结束IP"""
    begin = ""
    end = ""
    if "-" in strline:
        "xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx"
        begin, end = strline.split("-")
        if 1 <= len(end) <= 3:
            prefix = begin[0:begin.rfind(".")]
            end = prefix + "." + end
    elif strline.endswith("."):
        "xxx.xxx.xxx."
        begin = strline + "0"
        end = strline + "255"
    elif "/" in strline:
        "xxx.xxx.xxx.xxx/xx"
        (ip, bits) = strline.split("/")
        if checkipvalid(ip) and (0 <= int(bits) <= 32):
            orgip = from_string(ip)
            end_bits = (1 << (32 - int(bits))) - 1
            begin_bits = 0xFFFFFFFF ^ end_bits
            begin = to_string(orgip & begin_bits)
            end = to_string(orgip | end_bits)
    else:
        "xxx.xxx.xxx.xxx"
        begin = strline
        end = strline

    return begin, end


def dumpstacks():
    code = []
    for threadId, stack in sys._current_frames().items():
        code.append("\n# Thread: %d" % (threadId))
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                code.append("  %s" % (line.strip()))
    PRINT("\n".join(code))
    
def checksingleprocess(ipqueue,cacheResult,max_threads):
    threadlist = []
    threading.stack_size(96 * 1024)
    PRINT(u'需要创建的最大线程数：%d' % (max_threads))
    PRINT("=====================================================================")
    for i in xrange(1, max_threads + 1):
        ping_thread = Ping(ipqueue,cacheResult)
        ping_thread.setDaemon(True)
        try:
            ping_thread.start()
        except threading.ThreadError as e:
            PRINT('start new thread except: %s,work thread cnt: %d' % (e, Ping.getCount()))
            break
        threadlist.append(ping_thread)
    try:
        for p in threadlist:
            p.join()
    except KeyboardInterrupt:
        evt_ipramdomend.set()
    cacheResult.close()
    

def list_ping():
    if g_useOpenSSL == 1:
        PRINT(u"支持 PyOpenSSL")
    if g_usegevent == 1:
        PRINT(u"支持 gevent")

    checkqueue = Queue()
    cacheResult = TCacheResult()
    
    ramdomip_thread = RamdomIP(checkqueue,cacheResult)
    ramdomip_thread.setDaemon(True)
    ramdomip_thread.start()
    checksingleprocess(checkqueue,cacheResult,g_maxthreads)
    
    cacheResult.flushFailIP()
    ip_list = cacheResult.getIPResult()
    ip_list.sort()

    PRINT(u'                           开始整理结果')
    op = 'wb'
    if PY3:
        op = 'w'
    ff = open(g_ipfile, op)
    ncount = 0
    PRINT("=====================================================================")
    PRINT(u" 延迟(ms)         IP         服务端          证书")
    for ip in ip_list:
        domain = ip[2]
        # 只写入低于指定响应时间的IP
        if domain is not None and ip[0] <= g_maxhandletimeout:
            PRINT(u"   %s    %s    %s      %s" % (str(ip[0]).rjust(4), ip[1].ljust(15), ip[3], domain))
            if ncount > 0:
                ff.write("|")
            ff.write(ip[1])
            ncount += 1
    PRINT(u"文件 %s 写入完毕，IP 数量：%d " % (g_ipfile, ncount))
    ff.close()
    #未达到需要的IP数量时不清除临时文件，以便修改参数后复用数据
    if ncount >= g_maxhandleipcnt:
        cacheResult.clearFile()


if __name__ == '__main__':
    list_ping()
