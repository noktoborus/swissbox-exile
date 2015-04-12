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
import struct
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

def recv_message(s):
    write_std("# wait incoming...\n")
    b = s.recv(6)
    if not b:
        write_std("# zero result\n")
        return None
    if b[5] != '\0':
        write_std("# unknown packet: " + b.encode("hex") + "\n")
        return None
    ptypen = struct.unpack("!H", b[:2])[0]
    plen = struct.unpack("!I", "\0" + b[2:5])[0]
    if not ptypen in FEP.Type.values():
        write_std("# unknown packet type " + str(ptypen) + "\n")
        return None
    ptype = FEP.Type.keys()[ptypen - 1]
    write_std("# header: %s[%s]:%s\n" %(ptype, ptypen, plen))
    rawmsg = s.recv(plen)
    if rawmsg:
        try:
            msg = eval("FEP." + ptype[1:]).FromString(rawmsg)
            if hasattr(msg, "id"):
                write_std("# header id: %s\n" %(msg.id))
            else:
                write_std("# header has no id\n")
            if msg.__class__.__name__ == "FileUpdate":
                write_std("# fileUpdate")
                #__import__("pdb").set_trace()
                return recv_message(s)
            return (ptypen, ptype, msg)
        except:
            write_std("# exc %s" %str(sys.exc_info()))
            write_std("# header parse fail: %s (%s)\n" %(rawmsg.encode("hex"), len(rawmsg)))
    return None

def send_message(s, msg):
    ptype = FEP.Type.keys().index("t" + msg.__class__.__name__) + 1
    sl = msg.SerializeToString()
    ph = struct.pack("!H", ptype) + struct.pack("!I", len(sl))[1:] + '\0'
    try:
        write_std("# send id: %s, type: %s, len: (%s, %s)\n"\
                %(msg.id, msg.__class__.__name__), len(sl), len(ph))
    except:
        write_std("#send type: %s, len: (%s, %s)\n"\
                %(msg.__class__.__name__, len(sl), len(ph)))
    ph += sl
    s.send(ph)

def proto_bootstrap(s):
    while True:
        msgt = recv_message(s)
        if msgt:
            if msgt[1] == "tReqAuth":
                msg = FEP.Auth()
                msg.id = msgt[2].id
                msg.device_id = 4000
                msg.authType = FEP.tUserToken
                msg.domain = "it-grad.ru"
                msg.username = "some-user-name"#str(__import__("uuid").uuid1())
                msg.authToken = "1"
                send_message(s, msg)
            elif msgt[1] == "tOk":
                write_std("# auth ok\n")
                return True
            elif msgt[1] == "tError":
                write_std("# auth error: '%s', remain: %s\n"\
                        %(msgt[2].message, msgt[2].remain))
                return False
            elif msgt[1] == "tPendgin":
                write_std("# auth pending\n")
            else:
                write_std("# not an auth message\n")
        else:
            break
    return False

def proto(s, c):
    write_std("# orpot\n")
    if not proto_bootstrap(s):
        return
    if c == "ping":
        msg = FEP.Ping()
        msg.id = 100
        msg.timestamp = 0
        msg.usecs = 0
        send_message(s, msg)
    if c == "file":
        c = 1
        x = 10
        f = b"\0" * 65000
        ids = {}
        for q in range(0, c):
            msg = FEP.WriteAsk()
            msg.id = (2000 + q)
            guid = "64d68d0a-c1d0-11e4-be14-a417319a800m"
            ee = str(q)
            guid = guid[0:len(guid) - len(ee)] + ee
            msg.rootdir_guid = "6ad2e7b2-c1d0-11e4-be14-a417319a88f9"
            msg.file_guid = "653e17c2-c1d0-11e4-be14-a417319a88f9"
            msg.revision_guid = "038b0d98-c1d8-11e4-b23e-a417319a88f9"
            msg.chunk_guid = guid
            msg.chunk_hash = "\0\2\2\3"
            msg.size = len(f) * x
            send_message(s, msg)
            rmsg = recv_message(s)[2]
            ids[q] = rmsg.session_id
        for q in range(0, c):
            for qn in range(0, x):
                msg = FEP.xfer()
                msg.id = (2000 + q) * 100 + qn
                msg.session_id = ids[q]
                msg.data = f
                msg.offset = 0
                send_message(s, msg)
            msg = FEP.End()
        for q in range(0, c):
            msg.id = (2000 + q)
            msg.session_id = ids[q]
            msg.offset = 0
            msg.origin_len = 1
            send_message(s, msg)
            recv_message(s)
        msg = FEP.FileUpdate()
        msg.enc_filename = "123"
        msg.hash_filename = "123"
        msg.key = "123123"
        msg.id = 203
        msg.chunks = c
        msg.rootdir_guid = "6ad2e7b2-c1d0-11e4-be14-a417319a88f9"
        msg.revision_guid = "038b0d98-c1d8-11e4-b23e-a417319a88f9" 
        msg.file_guid = "653e17c2-c1d0-11e4-be14-a417319a88f9"
        send_message(s, msg)
        recv_message(s)
    if c == "wait":
        recv_message(s)
    if c == "chunk":
        __import__("pdb").set_trace()
        msg = FEP.QueryChunks()
        msg.id = 22
        msg.rootdir_guid =  "a0cf497f-8d04-437b-ade1-1c542a2c0e8b"
        msg.file_guid =     "810a931d-379c-465c-8cc7-c8ab5c8a643e"
        msg.revision_guid = "a298cb11-1f0e-4b1e-9577-c50ff8766dbc"
        send_message(s, msg)
        while recv_message(s)[0] != 4:
            pass
    if c == "read":
        msg = FEP.ReadAsk()
        msg.id = 223
        msg.session_id = 2
        msg.rootdir_guid = '1d2b1ce9-b3ab-40d3-86ec-3b771be9efcb'
        msg.file_guid = '5cfa6545-32b5-4b04-b3d0-70ecbab9c545'
        msg.chunk_guid = '45076c44-d617-42a0-a938-d0c121dde5c4'
        send_message(s, msg)
        while recv_message(s)[0] !=  11:
            pass
    if c == "wantsync":
        msg = FEP.WantSync()
        msg.id = 3004
        msg.with_slice = False
        msg.session_id = 500
        msg.checkpoint = 0
        send_message(s, msg)
        while recv_message(s):
            pass
    if c == "rename":
        msg = FEP.RenameChunk()
        msg.id = 300
        msg.rootdir_guid =  "a0cf497f-8d04-437b-ade1-1c542a2c0e8b"
        msg.file_guid =     "810a931d-379c-465c-8cc7-c8ab5c8a643e"
        msg.chunk_guid = "810a931d-379c-465c-8cc7-c8ab5c8a643e"
        msg.to_chunk_guid = "a298cb11-1f0e-4b1e-9577-c50ff8766dbc"
        msg.to_revision_guid = "a298cb11-1f0e-4b1e-9577-c50ff8766dbc"
        send_message(s, msg);
        recv_message(s)
    # TODO:

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
            p.poll()
            if p.returncode:
                write_std("# process exit with code %s\n" %(p.returncode))
                break
        if not consend:
            # get connect string
            li = re.findall("entry in ([0-9:\.]*),", li)
            if li:
                consend = True
                server_q.put(li[0])
    server_q.put(None)
    # что бы наверняка
    try: p.terminate()
    except: pass

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

