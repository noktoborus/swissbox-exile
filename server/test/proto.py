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
                write_std("# header id: %s, sid: %s\n"
                        %(msg.id, hasattr(msg, "session_id") and msg.session_id or None))
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
            write_std("# exc %s\n" %str(sys.exc_info()))
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
    write_std("# send id: %s, sid: %s, type: %s[%s], len: (%s, %s)\n"\
            %(hasattr(msg, 'id') and msg.id or None, hasattr(msg, 'session_id') and msg.session_id or None, msg.__class__.__name__, ptype, len(sl), len(ph)))
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

def recvFileChunk(s, rootdir, file_, chunk):
    write_std("get chunk '%s' from file '%s'\n" %(chunk, file_))
    # TODO
    return True

def recvFileRevision(s, rootdir, file_, revision):
    write_std("recv revision '%s'\n" %revision)
    # получаем список чанков файла и пытаемся их скачать
    msg = FEP.QueryChunks()
    msg.id = random.randint(1, 10000)
    msg.session_id = random.randint(10000, 20000)
    msg.rootdir_guid = rootdir
    msg.file_guid = file_
    msg.revision_guid = revision
    send_message(s, msg)
    _ok = True
    _chunks = []
    while True:
        # вместо Ok приходит FileMeta
        rmsg = recv_message(s, ["ResultChunk", "Error", "FileMeta", "End"])
        if rmsg.__class__.__name__ == "Error":
            write_std("query chunks error: %s\n" %(rmsg.message))
            _ok = False
            break
        if rmsg.__class__.__name__ == "End":
            write_std("query chunks end: sid=%s, packets=%s\n" %(rmsg.session_id, rmsg.packets))
            break
        if rmsg.__class__.__name__ == "FileMeta":
            write_std("file info: chunks=%s, enc_filename=%s, directory=%s, parent_revision=%s\n"
                    %(rmsg.chunks, rmsg.enc_filename, rmsg.directory_guid, hasattr(rmsg, 'parent_revision_guid') and rmsg.parent_revision_guid or None))
            continue
        # из ResultChunk можно получить адрес чанка и сам чанк
        _chunks.append(rmsg.chunk_guid)

    while _chunks:
        if not recvFileChunk(s, rootdir, file_, _chunks.pop()):
            return False
    return _ok

def recvFile(s, rootdir, path):
    _file_guid = str(uuid.UUID(bytes=hashlib.md5(path).digest()))
    write_std("recv file '%s' (%s, rootdir: %s)\n" %(path, _file_guid, rootdir))

    # сначала нужно получить ревизии файла
    msg = FEP.QueryRevisions()
    msg.id = random.randint(1, 10000)
    msg.session_id = random.randint(10000, 20000)
    msg.rootdir_guid = rootdir
    msg.file_guid = _file_guid
    msg.depth = 3
    send_message(s, msg)


    _rev = None

    # получаем ревизию
    _ok = True
    while True:
        rmsg = recv_message(s, ["ResultRevision", "Error", "Ok", "End"])
        if rmsg.__class__.__name__ == "Error":
            write_std("query revisions error: %s\n" %(rmsg.message))
            _ok = False
            break
        if rmsg.__class__.__name__ == "End":
            write_std("query revisions end: sid=%s, packets=%s\n" %(rmsg.session_id, rmsg.packets))
            break
        if rmsg.__class__.__name__ == "Ok":
            continue
        write_std("file %s, revision %s (%s/%s)\n" %(_file_guid, rmsg.revision_guid, rmsg.rev_no, rmsg.rev_max))
        _rev = rmsg.revision_guid

    if _rev:
        # обработка ResultRevision
        _ok = recvFileRevision(s, rootdir, _file_guid, _rev)
    else:
        _ok = False
        write_std("revision for file '%s' not received\n" %(_file_guid))
        
    if _ok:
        write_std("recv file '%s' complete\n" %(_file_guid))
    return _ok

def sendFile(s, rootdir, directory, path):
    _chunk_size = 1048576 # размер чанка
    _hash = None

    _size = os.path.getsize(path)
    _chunks = math.trunc(math.ceil(float(_size) / _chunk_size))

    write_std("send file '%s' into %s\n" %(path, rootdir))
    fmsg = FEP.FileMeta()
    wmsg = FEP.WriteAsk()

    # заполнение метаинформации файла
    fmsg.id = random.randint(1, 10000)
    fmsg.rootdir_guid = rootdir
    fmsg.directory_guid = directory
    fmsg.file_guid = str(uuid.UUID(bytes=hashlib.md5(path).digest()))
    fmsg.revision_guid = str(uuid.uuid4())

    fmsg.enc_filename = os.path.basename(path)
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


X_rootdir = None
X_directory = None
X_prefix = "/self/"
X_files = []

def proto_sync(s):
    global X_rootdir
    global X_directory
    global X_files
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

        if rmsg.__class__.__name__ in ("DirectoryUpdate"):
            write_std("%s name: %s\n" %(rmsg.__class__.__name__, rmsg.path));

        if rmsg.__class__.__name__ in ("FileUpdate"):
            if hasattr(rmsg, 'enc_filename') and hasattr(rmsg, 'directory_guid'):
                write_std("file update: %s\n" %(rmsg.enc_filename))
                X_files.append(rmsg.file_guid)
            else:
                write_std("file delete: %s\n" %(rmsg.file_guid))
                if rmsg.file_guid in X_files:
                    X_files.remove(rmsg.file_guid)

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
            if not X_directory and (hasattr(rmsg, "path") and rmsg.path == X_prefix):
                write_std("acquire directory=%s\n" %(rmsg.directory_guid))
                write_std("acquire rootdir=%s\n" %(rmsg.rootdir_guid))
                X_directory = rmsg.directory_guid
                X_rootdir = rmsg.rootdir_guid

        if rmsg.no == rmsg.max:
            write_std("# sync sid=%s complete\n" %(rmsg.session_id))

def mkdir(s, rootdir, path):
    msg = FEP.DirectoryUpdate()
    msg.id = random.randint(1, 10000)
    msg.rootdir_guid = rootdir
    msg.directory_guid = str(uuid.UUID(bytes=hashlib.md5(path).digest()))
    msg.path = path

    send_message(s, msg)
    write_std("mkdir %s with path %s\n" %(msg.directory_guid, path))
    rmsg = recv_message(s, ["Error", "OkUpdate"])
    if rmsg.__class__.__name__ == "Error":
        write_std("mkdir error: %s\n" %rmsg.message)
        return None
    else:
        write_std("mkdir created with checkpoint %s, message: %s\n"
                %(rmsg.checkpoint, maybe(rmsg, "message")))
        return msg.directory_guid

def maybe(msg, field):
    if hasattr(msg, field):
        return getattr(msg, field)
    return '-'

def examine(msg):
    _type = msg.__class__.__name__
    if _type == "Error":
        write_std("%% Error: (id: %s, remain: %s) %s\n"
                %(msg.id, maybe(msg, "remain"), maybe(msg, "message")))
        return

    if _type == "Ok":
        write_std("%% Ok: (id: %s): %s\n" %(msg.id, maybe(msg, "message")))
        return

    if _type == "DirectoryUpdate":
        write_std("%% Directory: (id: %s, sid: %s, rootdir: %s, %s) %s\n"
                %(msg.id, maybe(msg, "session_id"), msg.rootdir_guid,
                    msg.directory_guid, maybe(msg, "path")))
        return

    if _type == "FileUpdate":
        write_std("%% File: (id: %s, sid: %s, rootdir: %s, directory: %s, %s) %s\n"
                %(msg.id, maybe(msg, "session_id"), msg.rootdir_guid,
                    maybe(msg, "directory_guid"), msg.file_guid,
                    maybe(msg, "enc_filename")))
        return

    if _type == "OkUpdate":
        write_std("%% OkUpdate: (id: %s, sid: %s, checkpoint: %s): %s\n"
                %(msg.id, maybe(msg, "session_id"), msg.checkpoint, maybe(msg, "message")));

    write_std("%% %s: (id: %s, sid: %s)\n"
            %(_type, maybe(msg, "id"), maybe(msg, "session_id")))
    return

def proto(s, user, secret, devid):
    global X_files
    global X_rootdir
    global X_directory
    write_std("# orpot\n")
    if not proto_bootstrap(s, user, secret, devid):
        return
    while True:
        write_std('input queue len: %s\n' %(len(_input_queue)));
        c = input('help> ');

        if c == "help":
            write_std("ping, wait sync write mkdir remove\n")
            continue
        if c == "remove":
            pass
        if c == "rmdir":
            if not X_directory:
                write_std("# try to cmd `sync` or `mkdir` (rootdir: %s, directory: %s)\n" %(X_rootdir, X_directory))
                continue
            msg = FEP.DirectoryUpdate()
            msg.id  = random.randint(1, 10000)
            msg.rootdir_guid = X_rootdir
            msg.directory_guid = X_directory
            send_message(s, msg)
            rmsg = recv_message(s, ["Error", "OkUpdate"])
            examine(rmsg)

            continue
        if c == "mkdir":
            if not X_rootdir:
                write_std("# try to cmd `sync` (rootdir: %s)\n" %(X_rootdir))
                continue
            
            _x = mkdir(s, X_rootdir, X_prefix)
            if _x:
                write_std("acquire directory=%s\n" %(_x))
                X_directory = _x
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
        if c == "ewait":
            try:
                while True:
                    examine(recv_message(s))
            except KeyboardInterrupt:
                continue
        if c == "write":
            if not X_rootdir or not X_directory:
                write_std("# try to cmd `sync` or `mkdir` (rootdir: %s, directory: %s)\n" %(X_rootdir, X_directory))
                continue
            # вгружаем всё в текущей директории, кроме директорий и файлов с "."
            for _n in [x for x in os.walk('.') if not x[0].startswith('./.')]:
                # создаём директорию
                _d = mkdir(s, X_rootdir, X_prefix + _n[0])
                if not _d:
                    break
                for _f in _n[2]:
                    _f = _n[0] + '/' + _f 
                    if not sendFile(s, X_rootdir, _d, _f):
                        _d = None
                        break
                if not _d:
                    break

            continue
        if c == "read":
            if not X_rootdir:
                write_std("# try to cmd `sync` and `write` (rootdir: %s)\n" %(X_rootdir))
                continue
            for _n in [x for x in os.listdir('.') if os.path.isfile(x)]:
                if not recvFile(s, X_rootdir, _n):
                    break
        if c == "sync":
            proto_sync(s)
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

