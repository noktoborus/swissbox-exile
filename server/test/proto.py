#!/usr/bin/env python
# -*- encoding: utf-8 -*
# vim: ft=python ff=unix fenc=utf-8
# file: test/proto.py

import sys
sys.path.insert(0, "proto")
sys.path.insert(0, "../proto")

import fep_pb2 as FEP
import subprocess
import threading
import socket
import select
import Queue as queue
import os
import re

colors = {
    "red": "\033[1m",
    "yellow": "\033[3m",
    "green": "\033[2m",
    "_": "\033[0m"
        }

server_q = queue.Queue() # читать с сервер вотчера
server_p = queue.Queue() # слать на сервер вотчер
write_std_lock = threading.Lock()

def write_std(string, color = None):
    if len(string):
        write_std_lock.acquire()
        if color in colors:
            sys.stdout.write(colors[color] + string + colors["_"])
        else:
            sys.stdout.write(string);
        sys.stdout.flush()
        write_std_lock.release()
    return len(string)

def proto(s, c):
    write_std("# orpot\n")
    # TODO
    pass

def connect(host, command):
    write_std("# connect to %s\n" %host)
    sock = None
    port = "0"
    if ":" in host:
        e = host.rsplit(":", 1)
        host = e[0]
        port = e[1]
    for ai in\
        socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
        try:
            write_std("# use adddres info %s\n" %str(ai))
            sock = socket.socket(ai[0], ai[1], ai[2])
            sock.connect(ai[4])
        except:
            exc = sys.exc_info()
            write_std("# connect fail: " + str(exc) + "\n")
            sock = None
        if sock:
            proto(sock, command)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            break
    write_std("# end of sockets\n")


def thread_entry(): # сервер вотчер ололо
    consend = False
    p = subprocess.Popen(addr,
            stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    write_std("# process start: %s\n" %(p.pid))
    # крутим пока не появилось событие в очереди событий
    while server_p.empty():
        li = ""
        sss = select.select([p.stdout, p.stderr], [], [], 0.5)[0]
        # get lines
        for ss in sss:
            if ss == p.stdout:
                li += p.stdout.readline()
                write_std(li, "yellow")
            if ss == p.stderr:
                li += p.stderr.readline()
                write_std(li, "red")
        if not li:
            write_std("# process exit\n")
            break
        if not consend:
            # get connect string
            li = re.findall("entry in ([0-9:\.]*),", li)
            if li:
                consend = True
                server_q.put(li[0])
    server_q.put(None)
    p.terminate()

def run(addr, command):
    thx = threading.Thread(None, thread_entry, "ServerWatch")
    thx.start()
    try:
        c = server_q.get()
        if c:
            connect(c, command)
    except KeyboardInterrupt:
        write_std("# interrupt\n")
    write_std("# exit\n")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("use: %s <file|host[:port]> command" %sys.argv[0])
        sys.exit(-1)
    addr = sys.argv[1]
    command = sys.argv[2]
    if os.path.exists(addr):
        if not (os.path.isfile(addr) and os.access(addr, os.X_OK)):
            print("%s is not executable file", addr);
            sys.exit(-1)
        run(addr, command)
    else:
        connect(addr, command)

