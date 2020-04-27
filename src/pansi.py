#!/usr/bin/env python3
# Yonghang Wang

import os
import sys
from optparse import OptionParser
import re
import getpass
import pexpect
import string
import datetime
import threading
import socket
from queue import Queue
from multiprocessing.pool import Pool
from random import randrange

def main():
    parser = OptionParser()
    parser.add_option('-r', '--remote', dest='remote', help='remote servers')
    parser.add_option('-c',
                      '--command',
                      dest='command',
                      help='command to run remotely')
    parser.add_option('-f',
                      '--script',
                      dest='script',
                      help='script to run remotely')
    parser.add_option('-u', '--user', dest='user', help='user')
    parser.add_option('-p', '--password', dest='password', help='password')
    parser.add_option('-W',
                      '--worker',
                      dest='worker',
                      default=4,
                      help='max number of workers')
    parser.add_option(
        '-C',
        '--call',
        dest='call',
        default='{{THEONE}}',
        help='way to call script, work with -f. eg. \"python3 {{THEONE}}\"'
    )
    parser.add_option('-i',
                      '--pkey',
                      dest='pkey',
                      help='private key file for ssh')
    parser.add_option('-w',
                      '--workdir',
                      dest='workdir',
                      default='.cache/pansi',
                      help='cache dir for script on remote server')
    parser.add_option('-t',
                      '--timeout',
                      dest='timeout',
                      default=10,
                      help='default timeout. better > 5')
    parser.add_option('-O',
                      '--option',
                      dest='option',
                      default="",
                      help='extra option for ssh command')
    parser.add_option('-I',
                      '--init',
                      dest='init',
                      default='\r\n',
                      help='command to run after ssh connection established.')
    parser.add_option('-X',
                      '--debug',
                      action='store_true',
                      dest='debug',
                      default=False,
                      help='debug mode')
    parser.add_option('-R',
                      '--remove',
                      action='store_true',
                      dest='remove',
                      default=False,
                      help='remove script and log after run')
    parser.add_option('-s',
                      '--setterminal',
                      action='store_true',
                      dest='setterminal',
                      default=False,
                      help='set terminal size same to parent')
    parser.add_option('-A',
                      '--removeall',
                      action='store_true',
                      dest='removeall',
                      default=False,
                      help='with -R, remove all in remote cache')
    parser.add_option('-k',
                      '--rm_conflict_key',
                      action='store_true',
                      dest='rm_conflict_key',
                      default=False,
                      help='remove known_hosts item without confirmation. this is useful when a large number of target server being rebuilt frequently.')
    parser.add_option('-v',
                      '--verbose',
                      action='store_true',
                      dest='verbose',
                      default=False,
                      help='show more info eg. command/script name')
    parser.add_option('-T',
                      '--tmpfile',
                      action='store_true',
                      dest='tmpfile',
                      default=False,
                      help='use random temp name to avoid conflict')

    (options, args) = parser.parse_args()

    options.timeout = int(options.timeout)
    if options.timeout <= 0:
        options.timeout = 10

    def sshrun(rserver, command):
        output = ""
        good = True
        if options.debug:
            print("# [{}] command =  {}".format(rserver, command))
        port = "22"
        sport = ""
        if ":" in rserver:
            rserver, port = re.split(":", rserver)[:2]
            if not port:
                port = "22"
            sport = "-p " + str(port)
        nullinput = " -n "
        if not (options.command or options.script):
            nullinput = " "
            cols, rows = os.get_terminal_size()
        sshbase = "ssh " + "-o ConnectTimeout=" + str(options.timeout) + nullinput + "  -t  " + options.option + sport 
        if options.debug :
            print("# [{}] sshbase = {}".format(rserver,sshbase))
        if options.pkey:
            sshbase = sshbase + " -i " + options.pkey
        if '@' in rserver :
            sshbase +=  " "  + rserver
        else :
            sshbase +=  " " + options.user + '@' + rserver
        if command:
            if options.debug:
                print("# [{}] {}".format(rserver,
                                         sshbase + " \"" + command + "\""))
            child = pexpect.spawn(sshbase + " \"" + command + "\"", timeout=options.timeout)
        else:
            if options.debug:
                print("# [{}] {}".format(rserver, sshbase))
            child = pexpect.spawn(sshbase, timeout=options.timeout)
        printable = set(string.printable)
        old_r=-1
        good = True
        resent = False
        while True:
            r = child.expect([
                'want to continue connecting', 'assword:', 'ermission denied',
                '[\$#]', 'key verification failed', pexpect.TIMEOUT, pexpect.EOF
            ],
                             timeout=options.timeout)
            if r == 0:
                if options.debug:
                    print("# [{}] answer yes for continue connecting".format(
                        rserver))
                child.sendline('yes')
            if r == 1:
                if options.debug:
                    print("# [{}] Requesting password".format(rserver))
                if old_r == 1 :
                    print("# [{}] Repeated Requesting password".format(rserver))
                    child.close()
                    good = False
                    break
                child.sendline(options.password)
            if r == 2:
                if options.debug:
                    print("# [{}] wrong password".format(rserver))
                output += ("# [{}] wrong password".format(rserver))
                child.close()
                good = False
                break
            if r == 3:
                if options.debug:
                    print('# [{}] $/#'.format(rserver))
                child.sendline("\r\n")
                if options.setterminal:
                    child.sendline("stty cols {}".format(cols))
                    child.sendline("stty rows {}".format(rows))
                child.sendline(options.init)
                break
            if r == 4:
                content = child.before.decode()
                cmd = [ln.strip() for ln in content.splitlines() if re.match(r"\s*ssh-keygen -f.*?-R.*",ln)]
                if options.debug:
                    print("# [{}] key validation failed. target server may have been rebuilt.".format(rserver))
                    print("# [{}] pls check and remove needed from known_hosts.".format(rserver))
                else :
                    output += ("# [{}] key validation failed. target server may have been rebuilt.\n".format(rserver))
                    output += ("# [{}] pls check and remove needed from known_hosts.\n".format(rserver))
                if options.rm_conflict_key :
                    if options.debug:
                        print("# [{}] fixing known_hosts".format(rserver))
                    else :
                        output += ("# [{}] fixing known_hosts".format(rserver))
                    if len(cmd) > 0 :
                        for c in cmd :
                            os.system(c)
                    else :
                            os.system("ssh-keygen -f ~/.ssh/known_hosts -R {} > /dev/null 2>&1 ".format(rserver))
                else :
                    break
                if options.debug :
                    print("# resending request ...")
                child.close()
                if command:
                    if options.debug:
                        print("# [{}] {}".format(rserver,
                                                 sshbase + " \"" + command + "\""))
                    child = pexpect.spawn(sshbase + " \"" + command + "\"", timeout=options.timeout)
                else:
                    if options.debug:
                        print("# [{}] {}".format(rserver, sshbase))
                    child = pexpect.spawn(sshbase, timeout=options.timeout)
                resent = True
            if r == 5:
                output += ("# [{}] TIMEOUT during [{}]\n".format(
                    rserver, command))
                child.close()
                good = False
                break
            if r == 6 :
                if options.debug:
                    print("# [{}] EOF detected".format(rserver))
                if old_r == 4 and resent :
                    resent = False
                content = child.before.decode()
                if re.search(r'\S+', content):
                    lines = content.splitlines()
                    if re.search(r"\S+", lines[0]):
                        start = 0
                    else:
                        start = 1
                    if re.search(r"\S+", lines[-1]):
                        lines = lines[start:]
                    else:
                        lines = lines[start:-1]
                    for ln in lines:
                        output += ("".join(filter(lambda x: x in printable,
                                                  ln))) + "\n"
                break
            old_r = r
        child.interact()
        return (output,good)

    def scprun(command):
        if options.debug :
            print("# [scp] {}".format(command))
        output = ""
        child = pexpect.spawn(command, timeout=options.timeout)
        while True:
            """
            no key validation error here. as even when used as scp alternative,
            sshrun/mkdir is called first.
            """
            r = child.expect([
                'want to continue connecting', 'assword:', 'ermission denied',
                '[\$#]', pexpect.TIMEOUT, pexpect.EOF
            ],
                             timeout=options.timeout)
            if r == 0:
                if options.debug :
                    print("# [scp] answer yes")
                child.sendline('yes')
            if r == 1:
                if options.debug :
                    print("# [scp] paste password")
                child.sendline(options.password)
            if r == 2:
                output += (
                    "# [scp] Wrong password or permission. cannot login.\n")
                return False
            if r == 3:
                return True
            if r == 4:
                output += ("# [scp] Timeout during [{}]\n".format(command))
                return False
            if r == 5:
                content=child.before.decode()
                if re.search(r'\S+',content) :
                    print(content)
                break
        return True

    def sshfile(rserver, script):
        rsvr,port = re.split(':',rserver)
        luser = options.user
        if "@" in rsvr :
            luser,rsvr = re.split(r"@",rsvr)[:2]
        output = ""
        if not re.search(r"^/", options.workdir):
            o, good = sshrun(rserver, 'mkdir -p ~' + options.user + '/' + options.workdir)
            if not good :
                output += "# [{}] sshfile exited.".format(rserver)
                return output
        else:
            o, good = sshrun(rserver, 'mkdir -p ' + options.workdir)
            if not good :
                output += "# [{}] sshfile exited.".format(rserver)
                return output
        scpbase = "scp -q -P {} -o ConnectTimeout={} ".format(port,options.timeout)
        if options.pkey:
            scpbase = scpbase + " -i " + options.pkey
        basename = re.sub(r'.*\/', '', script)

        def randstr():
            allchar = string.ascii_letters + string.digits
            result = "".join(
                allchar[randrange(len(allchar))] for _ in range(30))
            return result

        if options.tmpfile:
            tmstr = "{date:%Y%m%d.%H%M%S}".format(date=datetime.datetime.now())
            randname = '_' + tmstr + '_' + randstr()
        else:
            randname = ''
        if re.search(r"^/", options.workdir):
            tgtfile = options.workdir + '/' + basename + randname
        else:
            tgtfile = '~' + luser + '/' + options.workdir + '/' + basename + randname
        tgtlog = tgtfile + ".log"
        go2workdir=""
        if os.path.isfile(script):
            if not scprun(scpbase + " " + script + " " + luser + '@' + rsvr + ":" + tgtfile) :
                return output
        elif os.path.isdir(script):
            sshrun(rserver, 'mkdir -p {}'.format(tgtfile))
            go2workdir="cd {}/{};".format(tgtfile,basename)
            if not scprun(scpbase + " -r " + script + " " + luser + '@' + rsvr + ":" + tgtfile)  :
                return output
            #sshrun(rserver, 'chmod -R 0755 ' + tgtfile)
        if os.path.isfile(script):
            tgtcmd = re.sub(r'\{\{THEONE\}\}', tgtfile, options.call)
        elif os.path.isdir(script):
            tgtcmd = re.sub(r'\{\{THEONE\}\}', tgtfile + "/" + basename,
                            options.call)
        if options.debug:
            print("# [{}] cmd = {}".format(rserver, tgtcmd))
        mnohup = re.search(r"^\s*nohup",tgtcmd) 
        mredirect = re.search(r"\>",tgtcmd)  or re.search(r"\&",tgtcmd)
        if mnohup or mredirect :
            res, _ = sshrun(rserver, go2workdir + "chmod -R 0755 " + tgtfile + ";  "  + tgtcmd )
        else :
            res, _ = sshrun(rserver, go2workdir + "chmod -R 0755 " + tgtfile + ";  "  + tgtcmd + " 2>&1 | tee " + tgtlog)
        if res:
            output += res
        if options.remove:
            if options.removeall:
                res,_ = sshrun(
                    rserver, 'rm -rf ' + '~' + luser + '/' +
                    options.workdir + '/' + '*')
            else:
                res,_ = sshrun(rserver, 'rm -rf ' + tgtfile + '*')
            if res:
                output += res
        return output

    if not options.remote:
        parser.print_help()
        sys.exit(-1)

    if not options.user:
        options.user = getpass.getuser()
    if not options.pkey and not options.password:
        options.password = getpass.getpass()

    if options.script and not (os.path.isfile(options.script) or
                               os.path.isdir(options.script)):
        print("# {} does not exist".format(options.script))
        sys.exit(-1)

    TASK_QUEUE = Queue()
    RESULT_QUEUE = Queue()
    END_OF_ALL = "__yx_end_of_work__"

    servers = [x for x in re.split(r',', options.remote) if x]
    for rserver in servers:
        TASK_QUEUE.put(rserver)
    if not options.script and not options.command:
        NUM_WORKER_THREAD = 1
    else:
        NUM_WORKER_THREAD = int(options.worker)
        if NUM_WORKER_THREAD > len(servers):
            NUM_WORKER_THREAD = len(servers)
    if options.debug:
        print("# using {} worker thread(s).".format(NUM_WORKER_THREAD))

    for _ in range(NUM_WORKER_THREAD):
        TASK_QUEUE.put(END_OF_ALL)

    def worker(id=-1):
        def porttest(host,port) :
            try :
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(options.timeout)
                s.connect((host,port))
            except :
                return False
            return True
        def runsvr(rsvr):
            output = ("# HOST : [" + rsvr + "]\n")
            port = "22"
            if ":" in rsvr:
                rsvr, port = re.split(":", rsvr)[:2]
                if not port:
                    port = "22"
            luser = None
            if "@" in rsvr :
                luser, rsvr = re.split("@", rsvr)[:2]
            if options.debug :
                print("# [worker {}] rsvr={}, luser={}, port={}".format(id, rsvr,luser,port))
            if not porttest(rsvr,int(port)) :
                output += ("# [worker {}] [{}] ssh port {} not reachable\n".format(id,rsvr,port))
                return output
            if luser :
                rsvr = luser + '@' + rsvr + ":" + port
            else :
                rsvr = rsvr + ":" + port
            if options.debug:
                print("# [worker {}] started working for {}".format(id, rsvr))
            if not re.search(r'\S+', rsvr):
                return
            if options.command:
                if options.verbose:
                    output += ("# [worker {}] command = {}\n".format(
                        id, options.command))
                res,_ = (sshrun(rsvr, options.command))
                output += res
            if options.script:
                if options.verbose:
                    output += ("# [worker {}] script  = {}\n".format(
                        id, options.script))
                output += (sshfile(rsvr, options.script))
            if not options.script and not options.command:
                res,_ = (sshrun(rsvr, None))
                output += res
            return output

        while True:
            rsvr = TASK_QUEUE.get()
            if rsvr == END_OF_ALL:
                break
            res = runsvr(rsvr)
            RESULT_QUEUE.put(res)
        RESULT_QUEUE.put(END_OF_ALL)
        if options.debug:
            print("# worker {} exited.".format(id))

    def collector():
        ended = 0
        while True:
            res = RESULT_QUEUE.get()
            if res == END_OF_ALL:
                ended += 1
                if ended >= NUM_WORKER_THREAD:
                    break
            else:
                print(res)

    threads = list()
    c = threading.Thread(target=collector)
    c.start()
    threads.append(c)
    for i in range(NUM_WORKER_THREAD):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
