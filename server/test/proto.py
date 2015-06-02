#!/usr/bin/env python
# -*- encoding: utf-8 -*
# vim: ft=python ff=unix fenc=utf-8
# file: test/proto.py

import sys
sys.path.insert(0, "proto")
sys.path.insert(0, "../proto")

import fep_pb2 as FEP
import hashlib
import subprocess
import threading
import socket
import select
import struct
import random
import uuid
import math
import Queue as queue
import os
import re

try: input = raw_input
except: pass

colors = {
    "red": "\033[1m",
    "yellow": "\033[3m",
    "green": "\033[2m",
    "_": "\033[0m"
        }

server_q = queue.Queue() # читать с сервер вотчера
server_p = queue.Queue() # слать на сервер вотчер
write_std_lock = threading.Lock()

_input_queue = []

def gen_device_id():
    pass

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

def _recv_message(s, expected = None):
    """
        ожидание сообщение.
        expected: список имён ожидаемых классов сообщений
    """
    if not expected:
        write_std("# wait incoming...\n")
    else:
        write_std("# wait one of %s\n" %str(expected))
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
            # печать ошибки, если не ожидается чтение вызвано без ожидания типа
            if msg.__class__.__name__ == 'Error' and\
                (type(expected) not in (list, tuple) or\
                    msg.__class__.__name__ not in expected):
                write_std("# recv error: %s (%s)\n" %(msg.message, msg.remain))
            if type(expected) in (list, tuple):
                if msg.__class__.__name__ not in expected:
                    write_std("# message %s (id: %s) not in %s\n" %(msg.__class__.__name__, hasattr(msg, 'id') and msg.id or None, expected))
                    _input_queue.append(msg)
                    #__import__("pdb").set_trace()
                    return recv_message(s, expected)
            return msg
        except:
            write_std("# exc %s" %str(sys.exc_info()))
            write_std("# header parse fail: %s (%s)\n" %(rawmsg.encode("hex"), len(rawmsg)))
    return None

def recv_message(s, expected = None):
    # костылинг типа
    if type(expected) == str:
        expected = (expected,)
    # проверка сообщений вначале в очереди
    if not expected and _input_queue:
        n = _input_queue.pop()
        write_std("# extract from queue: %s (id=%s)\n" %(n.__class__.__name__, n.id))
        return n
    elif expected and _input_queue:
        for n in _input_queue:
            if n.__class__.__name__ in expected:
                write_std("# match from queue: %s (id=%s)\n" %(n.__class__.__name__, n.id))
                _input_queue.remove(n)
                return n
    return _recv_message(s, expected)

def send_message(s, msg):
    ptype = FEP.Type.keys().index("t" + msg.__class__.__name__) + 1
    sl = msg.SerializeToString()
    ph = struct.pack("!H", ptype) + struct.pack("!I", len(sl))[1:] + '\0'
    try:
        write_std("# send id: %s, type: %s[%s], len: (%s, %s)\n"\
                %(msg.id, msg.__class__.__name__, ptype, len(sl), len(ph)))
    except:
        write_std("#send type: %s[%s], len: (%s, %s)\n"\
                %(msg.__class__.__name__, ptype, len(sl), len(ph)))
    ph += sl
    s.send(ph)

def proto_bootstrap(s, user, secret, devid):
    while True:
        rmsg = recv_message(s, ("ReqAuth", "Ok", "Pending", "Error"))
        if rmsg:
            if rmsg.__class__.__name__ == "ReqAuth":
                msg = FEP.Auth()
                msg.id = rmsg.id
                msg.device_id = 4000
                msg.authType = FEP.tUserToken
                msg.domain = "it-grad.ru"
                msg.username = user
                msg.authToken = secret
                msg.device_id = int(hashlib.md5(socket.gethostname() + devid).hexdigest()[:16], 16)
                send_message(s, msg)
            elif rmsg.__class__.__name__ == "Ok":
                write_std("# auth ok\n")
                return True
            elif rmsg.__class__.__name__ == "Error":
                write_std("# auth error: '%s', remain: %s\n"\
                        %(rmsg.message, rmsg.remain))
                return False
            elif rmsg.__class__.__name__ == "Pending":
                write_std("# auth pending\n")
            else:
                write_std("# not an auth message\n")
        else:
            break
    return False


def sendFile(s, rootdir, directory, path):
    _chunk_size = 1048576 # размер чанка
    _hash = None

    _size = os.path.getsize(path)
    _chunks = math.trunc(math.ceil(float(_size) / _chunk_size))

    write_std("send file '%s'\n" %path)
    fmsg = FEP.FileMeta()
    wmsg = FEP.WriteAsk()

    # заполнение метаинформации файла
    fmsg.id = random.randint(1, 10000)
    fmsg.rootdir_guid = rootdir
    fmsg.directory_guid = directory
    fmsg.file_guid = str(uuid.UUID(bytes=hashlib.md5(path).digest()))
    fmsg.revision_guid = str(uuid.uuid4())

    fmsg.enc_filename = path
    fmsg.key = "0"

    fmsg.chunks = _chunks

    # OkUpdate приходит в самом конце, бессмысленно его ждать сразу
    # после отправки FileMeta
    send_message(s, fmsg)

    # заполнение информации о чанке
    # общая информация для всех чанков файла
    wmsg.rootdir_guid = fmsg.rootdir_guid
    wmsg.file_guid = fmsg.file_guid
    wmsg.revision_guid = fmsg.revision_guid

    file_descr = open(path, "r")
    chunk_offset = 0
    _i = 0
    _ok = True
    for chunk_data in iter(lambda: file_descr.read(int(_chunk_size)), ""):
        wmsg.id = random.randint(1, 10000)
        wmsg.chunk_guid = str(uuid.uuid4())
        wmsg.chunk_hash = hashlib.sha256(chunk_data).digest()
        wmsg.size = len(chunk_data)
        wmsg.offset = chunk_offset
        chunk_offset += wmsg.size
        send_message(s, wmsg)
        # в ответе должно прийти session_id для передачи
        rmsg = recv_message(s, ["Error", "OkWrite"])
        if rmsg.__class__.__name__ == "Error":
            write_std("send file error: %s\n", msg.message)
            file_descr.seek(0)
            _ok = False
            break
        elif rmsg.__class__.__name__ == "OkWrite":
            # отправка чанков цельными кусками (по одному xfer)
            _i += 1
            write_std("send chunk no=%s with sid=%s\n" %(_i, rmsg.session_id))
            xmsg = FEP.xfer()
            xmsg.id = random.randint(1, 10000)
            xmsg.session_id = rmsg.session_id
            xmsg.offset = 0
            xmsg.data = chunk_data
            send_message(s, xmsg)
            # отправка сообщения о завершнии сесии
            # (только один пакет в сесcии был отправлен
            xmsg = FEP.End()
            xmsg.id = random.randint(1, 10000)
            xmsg.session_id = rmsg.session_id
            xmsg.packets = 1
            send_message(s, xmsg)
            # после отправки End должен прийти Ok или Error
            rmsg = recv_message(s, ["Ok", "Error"])
            if rmsg.__class__.__name__ == "Error":
                write_std("send file error: %s\n" %rmsg.message)
                file_descr.seek(0)
                _ok = False
                break
            elif rmsg.__class__.__name__ == "Ok":
                write_std("send chunk complete\n")
    if file_descr.tell() == _size or _ok:
        # после отправки всех чанков должен прийти OkUpdate
        # если отправка завершилась успешно
        rmsg = recv_message(s, ["OkUpdate", "Error"])
        if rmsg.__class__.__name__ == 'Error':
            write_std("file compilation failed: %s\n" %rmsg.message)
            return False
        write_std("send file ok, checkpoint=%s\n" %(rmsg.checkpoint))
        return True
    return False


def proto(s, user, secret, devid):
    write_std("# orpot\n")
    X_rootdir = None
    X_directory = None
    if not proto_bootstrap(s, user, secret, devid):
        return
    while True:
        write_std('input queue len: %s\n' %(len(_input_queue)));
        c = input('help> ');

        if c == "help":
            write_std("ping, wait sync write mkdir\n")
            continue
        if c == "ping":
            msg = FEP.Ping()
            msg.id = 100
            msg.sec = 0
            msg.usec = 0
            send_message(s, msg)
            msg = recv_message(s, "Pong")
            write_std("# pong ok!\n")
            continue
        if c == "wait":
            recv_message(s)
            continue
        if c == "write":
            if not X_rootdir or not X_directory:
                write_std("# try to cmd `sync` or `mkdir` (rootdir: %s, directory: %s)\n" %(X_rootdir, X_directory))
                continue
            for _n in [x for x in os.listdir('.') if os.path.isfile(x)]:
                if not sendFile(s, X_rootdir, X_directory, _n):
                    break
            continue
        if c == "sync":
            _sessions = []
            _oks = []
            _session_id = 100
            _id = 200
            msg = FEP.WantSync()
            msg.id = _id
            msg.checkpoint = 0
            msg.session_id = _session_id
            send_message(s, msg)
            _sessions.append(msg.session_id)
            _oks.append(msg.id)
            while True:
                if not _sessions:
                    break;
                rmsg = recv_message(s, ("FileUpdate", "RootdirUpdate", "DirectoryUpdate", "Error", "Ok", "End"))
                if not rmsg:
                    write_std("# eof\n")
                    break
                if rmsg.__class__.__name__ == "Ok":
                    if rmsg.id not in _oks:
                        write_std("# sync exception: ok id: %s, expected: %s\n" %(rmsg.id, str(_oks)))
                        break
                    else:
                        write_std("# sync id=%s ok\n" %rmsg.id)
                        _oks.remove(rmsg.id)
                        continue
                if rmsg.__class__.__name__ == "End":
                    write_std("# sync sid=%s ended, messages: %s\n" %(rmsg.session_id, rmsg.packets))
                    _sessions.remove(rmsg.session_id)
                    continue

                if rmsg.__class__.__name__ == "Error":
                    write_std("# sync error: %s\n" %rmsg.message)
                    break

                elif rmsg.session_id not in _sessions:
                    write_std("# sync exception: sessid got %s, expect %s\n" %(rmsg.session_id, str(_sessions)))
                    break

                if rmsg.__class__.__name__ in ("FileUpdate", "DirectoryUpdate", "RootdirUpdate"):
                    write_std("%s checkpoint: %s (rootdir: %s) [%s: %s/%s]\n" %(rmsg.__class__.__name__, rmsg.checkpoint, rmsg.rootdir_guid, rmsg.session_id, rmsg.no, rmsg.max))

                if rmsg.__class__.__name__ in ("RootdirUpdate"):
                    _id += 1
                    _session_id += 1
                    nmsg = FEP.WantSync()
                    nmsg.id = _id
                    nmsg.rootdir_guid = rmsg.rootdir_guid
                    nmsg.checkpoint = rmsg.checkpoint
                    nmsg.session_id = _session_id
                    _sessions.append(nmsg.session_id)
                    _oks.append(nmsg.id)
                    write_std("Sync in %s (%s): sid -> %s\n" %(rmsg.rootdir_guid, rmsg.name, nmsg.session_id))
                    send_message(s, nmsg)
                    if not X_rootdir:
                        write_std("acquire rootdir=%s\n" %(rmsg.rootdir_guid))
                        X_rootdir = rmsg.rootdir_guid

                if rmsg.__class__.__name__ in ("DirectoryUpdate"):
                    if not X_rootdir:
                        write_std("acquire rootdir=%s\n" %(rmsg.rootdir_guid))
                        X_rootdir = rmsg.rootdir_guid
                    if not X_directory:
                        write_std("acquire directory=%s\n" %(rmsg.directory_guid))
                        X_directory = rmsg.directory_guid

                if rmsg.no == rmsg.max:
                    write_std("# sync sid=%s complete\n" %(rmsg.session_id))


            continue

def connect(host, user, secret, devid):
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
            proto(sock, user, secret, devid)
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

def run(addr, user, secret, devid):
    thx = threading.Thread(None, thread_entry, "ServerWatch")
    thx.start()
    try:
        c = server_q.get()
        if c:
            connect(c, user, secret, devid)
    except KeyboardInterrupt:
        write_std("# interrupt\n")
    write_std("# exit\n")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("use: %s <file|host[:port]> user secret device_id" %sys.argv[0])
        sys.exit(-1)
    addr = sys.argv[1]
    user = sys.argv[2]
    secret = sys.argv[3]
    devid = sys.argv[4]
    if os.path.exists(addr):
        if not (os.path.isfile(addr) and os.access(addr, os.X_OK)):
            print("%s is not executable file", addr);
            sys.exit(-1)
        run(addr, user, secret, devid)
    else:
        connect(addr, user, secret, devid)

