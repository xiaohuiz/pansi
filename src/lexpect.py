#!/usr/bin/env python3
# Yonghang Wang

import os
import sys
from optparse import OptionParser
import re
import getpass
import pexpect
import string
import json

def main():
    parser = OptionParser()
    parser.add_option('-c', '--command', dest='command', help='command to spawn')
    parser.add_option('-r', '--rule', action="append",dest='rules', help="rules to follow")
    parser.add_option('-C', '--constant', action="append",dest='constants', help="define constant to use")
    parser.add_option('-T', '--whentimeout', dest='whentimeout', default=None, help="action when timeout")
    parser.add_option('-E', '--wheneof', dest='wheneof', default=None, help="action when eof")
    parser.add_option('-P', '--whenprompt', dest='whenprompt', default='[\$#]->%BREAK', help="action when meet with $ or #")
    parser.add_option('-t', '--timeout', dest='timeout', default=10, help="timeout")
    parser.add_option('-X', '--debug', dest='debug', action="store_true",default=False, help="debug mode")
    options,args = parser.parse_args()

    if not options.command :
        parser.print_help()
        sys.exit(0)

    consts = dict()
    if options.constants :
        rs = [re.split(r"\-\>",r) for r in options.constants]
        for arr in rs :
            k,v = arr[0],arr[1]
            if v == "INPUT" :
                v = input("% " + k + " : ")
            elif v == "PASSWORD" :
                v = getpass.getpass("% " + k + " : ")
            consts[k] = v
    if options.debug and len(consts) > 0 :
        print("# consts = {}".format(consts))

    prompt="[\$#]"
    promptact="%BREAK"
    m = re.search(r"(\S+)\->(\S+)",options.whenprompt)
    if m :
        prompt = m.group(1)
        promptact = m.group(2)
    if options.rules :
        rs = [re.split(r"\-\>",r) for r in options.rules]
    else :
        rs = list()
    patterns = [pexpect.TIMEOUT,pexpect.EOF,prompt] + [ x[0] for x in rs ]
    response = [options.whentimeout,options.wheneof,promptact] + [ x[1] for x in rs ]
    new_response = list()
    for r in response :
        if not r  :
            new_response.append(r) 
            continue
        m = re.search(r"\{\{(\S+)\}\}",r) 
        if m :
            k = m.group(1)
            if k in consts :
                r = re.sub("\{\{"+k+"\}\}",consts[k],r)
        new_response.append(r) 
    response = new_response
    if options.debug :
        print("# patterns = {}".format(patterns))
        print("# response = {}".format(response))

    printable = set(string.printable)
    child = pexpect.spawn(options.command, timeout=options.timeout)

    # act functions
    def print_content() :
        content = child.before.decode() 
        if child.after : 
            try :
                content += child.after.decode()
            except :
                pass
        if re.search(r'\S+', content):
            lines = content.splitlines()
            output = ""
            for ln in lines:
                output += ("".join(filter(lambda x: x in printable, ln))) + "\n"
            print(output)

    while True :
        r = child.expect(patterns)
        if options.debug :
            print("# Matched : {} (r={})".format(patterns[r],r))
        # timeout
        if r == 0 :
            print_content()
            break
        # EOF 
        if r == 1 :
            print_content()
            break
        if options.debug :
            print_content()

        rsp = response[r]
        if not rsp :
            break

        actlst = re.split(r";",rsp)
        if options.debug :
            print("# actlst = {}".format(actlst))

        for rsp in actlst :
            if rsp.upper() == "%BREAK" :
                child.sendline("\r\n")
                break
            if re.search(r"%CMD=(\S+)", rsp.upper()) :
                command = re.sub(r"%(CMD|cmd)=","",rsp,count=1) 
                if options.debug :
                    print("# runcmd : {}".format(command))
                os.system(command)
            if rsp.upper() == "%RESPAWN" :
                if options.debug :
                    print("# respawning")
                child.close()
                child = pexpect.spawn(options.command, timeout=options.timeout)
                continue
            if options.debug :
                print("# sendline : {}".format(response[r]))
            child.sendline(rsp)
    child.interact()

if __name__ == "__main__":
    main()
