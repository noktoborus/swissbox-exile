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
        s.recv(plen)
        return None
    ptype = FEP.Type.keys()[ptypen - 1]
    rawmsg = s.recv(plen)
    if len(rawmsg) != plen:
        write_std("# header message not readed: want %s bytes, received %s bytes, wait more\n" %(plen, len(rawmsg)))
        rawmsg += s.recv(plen - len(rawmsg))
    write_std("# header: %s[%s]:%s <- %s\n" %(ptype, ptypen, plen, len(rawmsg)))
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
                msg.authType = FEP.tUserToken
                msg.domain = "it-grad.ru"
                msg.username = user
                msg.authToken = secret
                msg.device_id = int(hashlib.md5(socket.gethostname() + str(devid)).hexdigest()[:16], 16)
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
    msg = FEP.ReadAsk()
    msg.id = random.randint(1, 10000)
    msg.session_id = random.randint(10000, 20000)
    msg.rootdir_guid = rootdir
    msg.file_guid = file_
    msg.chunk_guid = chunk
    send_message(s, msg)

    while True:
        rmsg = recv_message(s, ["OkRead", "Error", "xfer", "End"])
        examine(rmsg)
        if rmsg.__class__.__name__  == "Error":
            return False
        if rmsg.__class__.__name__ in ["Error", "End"]:
            break

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
    _directory = None
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
            examine(rmsg)
            _directory = rmsg.directory_guid
            continue
        # из ResultChunk можно получить адрес чанка и сам чанк
        _chunks.append(str(rmsg.chunk_guid))

    r_chunks = tuple(_chunks)
    while _chunks:
        if not recvFileChunk(s, rootdir, file_, _chunks.pop()):
            return None
    if not _ok:
        return None
    return (str(revision), str(_directory), r_chunks)

def _recvFile(s, rootdir, file_guid, devid):

    # сначала нужно получить ревизии файла
    msg = FEP.QueryRevisions()
    msg.id = random.randint(1, 10000)
    msg.session_id = random.randint(10000, 20000)
    msg.rootdir_guid = rootdir
    msg.file_guid = file_guid
    msg.depth = 3
    send_message(s, msg)

    _rev = None

    # получаем ревизию
    _ok = None
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
        write_std("file %s, revision %s (%s/%s)\n" %(file_guid, rmsg.revision_guid, rmsg.rev_no, rmsg.rev_max))
        _rev = rmsg.revision_guid

    if _rev:
        # обработка ResultRevision
        _ok = recvFileRevision(s, rootdir, file_guid, _rev)
    else:
        _ok = None
        write_std("revision for file '%s' not received\n" %(file_guid))

    if _ok:
        _ok = (file_guid, _ok)
        write_std("recv file '%s' complete (data: %s)\n" %(file_guid, str(_ok)))
        return _ok
    return None

def recvFileG(s, rootdir, file_guid, devid):
    write_std("recv file (%s, rootdir: %s)\n" %(file_guid, rootdir))
    return _recvFile(s, rootdir, file_guid, devid)

def recvFileF(s, rootdir, path, devid):
    _file_guid = str(uuid.UUID(bytes=hashlib.md5(path + "@" + str(devid)).digest()))
    write_std("recv file '%s' (%s, rootdir: %s)\n" %(path, _file_guid, rootdir))
    return _recvFile(s, rootdir, _file_guid, devid)

def updateRevision(s, rootdir, file_guid, directory, revision_guid, chunks, devid):
    r = True
    if not chunks:
        write_std("no chunks -- no work\n")
        return True
    new_revision = str(uuid.UUID(bytes=hashlib.md5(revision_guid + "@" + str(devid)).digest()))
    write_std("work with %s\n" %(str(chunks)))
    for chunk in chunks:
        msg = FEP.RenameChunk()
        msg.id = random.randint(1, 10000)
        msg.rootdir_guid = rootdir
        msg.file_guid = file_guid
        msg.chunk_guid = chunk
        msg.to_revision_guid = new_revision
        msg.to_chunk_guid = str(uuid.UUID(bytes=hashlib.md5(chunk + "@" + str(devid)).digest()))
        write_std("link chunk %s to revision %s (new uuid: %s)\n"
                %(chunk, new_revision, msg.to_chunk_guid))
        send_message(s, msg)
        rmsg = recv_message(s, ["Error", "Ok"])
        examine(rmsg)
        if rmsg.__class__.__name__ == "Error":
            r = False
            break
    if r:
        msg = FEP.FileMeta()
        msg.id = random.randint(1, 10000)
        msg.parent_revision_guid = revision_guid
        msg.rootdir_guid = rootdir
        msg.directory_guid = directory
        msg.file_guid = file_guid
        msg.revision_guid = new_revision
        msg.chunks = len(chunks)
        send_message(s, msg)
        rmsg = recv_message(s, ["Ok", "OkUpdate", "Error"])
        examine(rmsg)
        if rmsg.__class__.__name__ == "Error":
            r = False
    return r

def sendFile(s, rootdir, directory, path, devid):
    _chunk_size = 65536 # размер чанка
    _hash = None

    try: _size = os.path.getsize(path)
    except:
        write_std("send file '%s': file not found" %path)
        return False
    _chunks = math.trunc(math.ceil(float(_size) / _chunk_size))

    write_std("send file '%s' into %s\n" %(path, rootdir))
    wmsg = FEP.WriteAsk()

    zfmsg = FEP.FileMeta()
    zfmsg.id = random.randint(1, 10000)
    zfmsg.rootdir_guid = rootdir
    zfmsg.directory_guid = directory
    zfmsg.file_guid = str(uuid.UUID(bytes=hashlib.md5(path + "@" + str(devid)).digest()))
    zfmsg.revision_guid = str(uuid.uuid4())
    zfmsg.enc_filename = os.path.basename(path)
    zfmsg.key = "0"
    zfmsg.chunks = 0

    # инициализация файла
    send_message(s, zfmsg)

    # заполнение метаинформации файла
    fmsg = FEP.FileMeta()
    fmsg.id = random.randint(1, 10000)
    fmsg.rootdir_guid = rootdir
    fmsg.directory_guid = directory
    fmsg.file_guid = zfmsg.file_guid
    fmsg.revision_guid = str(uuid.uuid4())
    fmsg.parent_revision_guid = zfmsg.revision_guid

    fmsg.enc_filename = zfmsg.enc_filename
    fmsg.key = zfmsg.key

    fmsg.chunks = _chunks

    # после отправки всех чанков должен прийти OkUpdate
    send_message(s, fmsg)

    nfmsg = FEP.FileMeta()
    nfmsg.id = random.randint(1, 10000)
    nfmsg.rootdir_guid = fmsg.rootdir_guid
    nfmsg.directory_guid = fmsg.directory_guid
    nfmsg.file_guid = fmsg.file_guid
    nfmsg.revision_guid = str(uuid.uuid4())
    nfmsg.parent_revision_guid = fmsg.revision_guid
    nfmsg.chunks = 0

    # отправка перекрывающего сообщения, что бы воспроизвести DDB-235
    # заключается в том, что если отправлять первую ревизию (rev1)
    # с большим количеством чанков, а следом отправить ещё одну (rev2) с parent_revision=rev1
    # то rev2 получит отказ, т.к. rev1 ещё не собрана на сервере
    send_message(s, nfmsg)


    # OkUpdate приходит в самом конце, бессмысленно его ждать сразу
    # после отправки FileMeta

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
        wmsg.session_id = random.randint(10000, 20000)
        wmsg.chunk_guid = str(uuid.uuid4())
        wmsg.chunk_hash = hashlib.sha256(chunk_data).digest()
        wmsg.size = len(chunk_data)
        wmsg.offset = chunk_offset
        chunk_offset += wmsg.size
        send_message(s, wmsg)
        # в ответе должно прийти session_id для передачи
        rmsg = recv_message(s, ["Error", "OkWrite", "Satisfied"])
        if rmsg.__class__.__name__ == "Error":
            write_std("send file error: %s\n" %rmsg.message)
            file_descr.seek(0)
            _ok = False
            break
        elif rmsg.__class__.__name__ == "Satisfied":
            _i += 1
            write_std("skip chunk no=%s\n" %(_i))
            continue
        elif rmsg.__class__.__name__ == "OkWrite":
            # отправка чанков цельными кусками (по одному xfer)
            _i += 1
            write_std("send chunk no=%s with sid=%s\n" %(_i, wmsg.session_id))
            xmsg = FEP.xfer()
            xmsg.id = random.randint(1, 10000)
            xmsg.session_id = wmsg.session_id
            xmsg.offset = 0
            xmsg.data = chunk_data
            send_message(s, xmsg)
            # отправка сообщения о завершнии сесии
            # (только один пакет в сесcии был отправлен
            xmsg = FEP.End()
            xmsg.id = random.randint(1, 10000)
            xmsg.session_id = wmsg.session_id
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
        # если отправка завершилась успешно
        for x in (1, 2):
            # должно прийти два OkUpdate
            rmsg = recv_message(s, ["OkUpdate", "Error"])
            if rmsg.__class__.__name__ == 'Error':
                write_std("file compilation failed: %s\n" %rmsg.message)
                return False
            write_std("send file ok, checkpoint=%s\n" %(rmsg.checkpoint))
        return True
    return False

def deleteFile(s, rootdir, path, devid):
    msg = FEP.FileUpdate()
    msg.id = random.randint(1, 10000)
    msg.rootdir_guid = rootdir
    msg.file_guid = str(uuid.UUID(bytes=hashlib.md5(path + "@" + str(devid)).digest()))
    send_message(s, msg)
    rmsg = recv_message(s, ["Error", "OkUpdate"])
    examine(rmsg)
    if rmsg.__class__.__name__ == "Error":
        return False
    return True


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
    r = True
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
        rmsg = recv_message(s, ("FileUpdate", "RootdirUpdate", "DirectoryUpdate", "Error", "Ok", "End", "State"))
        if not rmsg:
            write_std("# eof\n")
            r = False
            break
        if rmsg.__class__.__name__ == "Ok":
            if rmsg.id not in _oks:
                write_std("# sync exception: ok id: %s, expected: %s\n" %(rmsg.id, str(_oks)))
                r = False
                break
            else:
                write_std("# sync id=%s ok\n" %rmsg.id)
                _oks.remove(rmsg.id)
                continue
        if rmsg.__class__.__name__ == "State":
            examine(rmsg)
            continue

        if rmsg.__class__.__name__ == "End":
            write_std("# sync sid=%s ended, messages: %s\n" %(rmsg.session_id, rmsg.packets))
            _sessions.remove(rmsg.session_id)
            continue

        if rmsg.__class__.__name__ == "Error":
            write_std("# sync error: %s\n" %rmsg.message)
            r = False
            break

        elif rmsg.session_id not in _sessions:
            examine(rmsg)
            write_std("# sync exception: sessid got %s, expect %s\n" %(rmsg.session_id, str(_sessions)))
            r = False
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
    return r

def mkdir(s, rootdir, path, remove = False):
    msg = FEP.DirectoryUpdate()
    msg.id = random.randint(1, 10000)
    msg.rootdir_guid = rootdir
    msg.directory_guid = str(uuid.UUID(bytes=hashlib.md5(path).digest()))

    if not remove:
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

    if not msg:
        return False

    if _type == "Error":
        write_std("%% Error: (id: %s, remain: %s) %s\n"
                %(msg.id, maybe(msg, "remain"), maybe(msg, "message")))
        return True

    if _type == "Ok":
        write_std("%% Ok: (id: %s): %s\n" %(msg.id, maybe(msg, "message")))
        return True

    if _type == "DirectoryUpdate":
        write_std("%% Directory: [%s] (id: %s, sid: %s, rootdir: %s, %s) %s\n"
                %(maybe(msg, "checkpoint"), msg.id, maybe(msg, "session_id"), msg.rootdir_guid,
                    msg.directory_guid, maybe(msg, "path")))
        return True

    if _type == "FileUpdate":
        write_std("%% File: [%s] (id: %s, sid: %s, rootdir: %s, directory: %s, %s) %s\n"
                %(maybe(msg, "checkpoint"), msg.id, maybe(msg, "session_id"), msg.rootdir_guid,
                    maybe(msg, "directory_guid"), msg.file_guid,
                    maybe(msg, "enc_filename")))
        return True
    
    if _type == "Chat":
        write_std("%% %s: (id: %s, sid: %s, user_from: %s, device_id_from: %s, user_to: %s, device_id_to: %s): %s\n"
            %(_type, maybe(msg, "id"), maybe(msg, "session_id"),
                maybe(msg, "user_from"), msg.device_id_from,
                maybe(msg, "user_to"), maybe(msg, "device_id_to"),
                msg.message))
        return True

    if _type == "OkUpdate":
        write_std("%% OkUpdate: [%s] (id: %s, sid: %s): %s\n"
                %(msg.checkpoint, msg.id, maybe(msg, "session_id"), maybe(msg, "message")))
        return True

    if _type == "xfer":
        write_std("%% %s: (id: %s, sid: %s, offset: %s, len: %s)\n"
                %(_type, maybe(msg, "id"), maybe(msg, "session_id"), msg.offset, len(msg.data)))
        return True

    if _type == "OkRead":
        write_std("%% %s: (id: %s, sid: %s, offset: %s, size: %s)\n"
                %(_type, maybe(msg, "id"), maybe(msg, "session_id"), msg.offset, msg.size))
        return True

    if _type == "State":
        write_std("%% %s: (id: %s, devices: %s, last_auth_device: %s, last_auth_time: %s last_auth_addr: %s)\n"
                %(_type, maybe(msg, "id"), maybe(msg, "devices"), maybe(msg, "last_auth_device"), maybe(msg, "last_auth_time"), maybe(msg, "last_auth_addr")))
        return True

    if _type == "ResultDevice":
        write_std("%% %s: (id: %s, session_id: %s, no: %s, max: %s) device: %s, last_auth_time: %s, is_online: %s\n"
                %(_type, msg.id, maybe(msg, "session_id"), maybe(msg, "no"),
                    maybe(msg, "max"), msg.device_id, msg.last_auth_time, msg.is_online))
        return True

    if _type == "StoreValue":
        write_std("%% %s: (id: %s) size: %s, store: {'%s'}\n"
                %(_type, msg.id, msg.size, msg.store))

    write_std("%% %s: (id: %s, sid: %s)\n"
            %(_type, maybe(msg, "id"), maybe(msg, "session_id")))
    return True

def proto(s, user, secret, devid, cmd = None):
    global X_files
    global X_rootdir
    global X_directory
    _file_readed = []
    write_std("# orpot\n")
    if not proto_bootstrap(s, user, secret, devid):
        return
    r = True
    if type(cmd) == str:
        cmd = [cmd,]
    elif type(cmd) == tuple:
        cmd = list(cmd)
    if cmd:
        cmd.reverse()
    while (type(cmd) == list and cmd and r) or cmd is None:
        g = ""
        c = ""
        a = ""
        write_std('input queue len: %s\n' %(len(_input_queue)))
        if cmd:
            c = cmd.pop()
        elif g != "" and not g is None:
            c = g
            g = ""
        elif cmd is None:
            c = input('help> ');
            if ' ' in c:
                c = c.split(' ', 1)
                a = c[1]
                c = c[0]

        if c == "help":
            write_std("ping, wait sync write mkdir remove roar\n")
            continue
        if c == "devices":
            msg = FEP.QueryDevices()
            msg.id = random.randint(1, 10000)
            msg.session_id = random.randint(10000, 20000)
            send_message(s, msg)
            rmsg = recv_message(s, ["Ok", "Error"])
            examine(rmsg)
            if rmsg.__class__.__name__ == "Ok":
                while True:
                    rmsg = recv_message(s, ["End", "ResultDevice"])
                    examine(rmsg)
                    if rmsg.__class__.__name__ == "End":
                        break
        if c == "maxdir":
            l = ["/path1/", "/path2", "/apth3/adas", "/asdri/a1i4", "/dkoq2/4"]
            
            for q in l:
                if not mkdir(s, X_rootdir, q):
                    r = False
                    break

            for q in l:
                if not mkdir(s, X_rootdir, q, True):
                    r = False
                    break
            continue
        if c == "roar":
            msg = FEP.Chat()
            msg.id = random.randint(1, 10000)
            msg.device_id_from = int(hashlib.md5(socket.gethostname() + str(devid)).hexdigest()[:16], 16)
            msg.message = "XXXF!"
            send_message(s, msg);
            rmsg = recv_message(s, ["Ok", "Error"])
            examine(rmsg);
            continue
        if c == "roaruni":
            msg = FEP.Chat()
            msg.id = random.randint(1, 10000)
            msg.device_id_from = int(hashlib.md5(socket.gethostname() + str(devid)).hexdigest()[:16], 16)
            msg.device_id_to = int('8DB7521C8E86DB89', 16)
            msg.message = "XXEDQ"
            send_message(s, msg)
            rmsg = recv_message(s, ["Ok", "Error"])
            examine(rmsg)
        if c == "remove":
            if not X_directory:
                write_std("# try to cmd `sync` or `mkdir` (rootdir: %s, directory: %s)\n" %(X_rootdir, X_directory))
                r = False
                continue

            for _n in [x for x in os.walk('.') if not x[0].startswith('./user')]:
                # создаём директорию
                _d = mkdir(s, X_rootdir, X_prefix + _n[0])
                if not _d:
                    r = False
                    break
                for _f in _n[2]:
                    _f = _n[0] + '/' + _f
                    if not deleteFile(s, X_rootdir, _f, devid):
                        _d = None
                        r = False
                        break
                if not _d or not r:
                    break

        if c == "rmdir":
            if not X_directory:
                write_std("# try to cmd `sync` or `mkdir` (rootdir: %s, directory: %s)\n" %(X_rootdir, X_directory))
                r = False
                continue
            msg = FEP.DirectoryUpdate()
            msg.id  = random.randint(1, 10000)
            msg.rootdir_guid = X_rootdir
            msg.directory_guid = X_directory
            send_message(s, msg)
            rmsg = recv_message(s, ["Error", "OkUpdate"])
            examine(rmsg)
            if rmsg.__class__.__name__ == "Error":
                r = False
            continue
        if c == "mkdir":
            if not X_rootdir:
                r = False
                write_std("# try to cmd `sync` (rootdir: %s)\n" %(X_rootdir))
                continue

            _x = mkdir(s, X_rootdir, X_prefix)
            if _x:
                write_std("acquire directory=%s\n" %(_x))
                X_directory = _x
            else:
                r = False
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
                    rmsg = recv_message(s)
                    if rmsg.__class__.__name__ == "FileUpdate":
                        if not recvFileG(s, X_rootdir, rmsg.file_guid, devid):
                            break
                    if not examine(rmsg):
                        break
            except KeyboardInterrupt:
                continue
        if c == "send":
            if not X_rootdir or not X_directory:
                r = False
                write_std("# try to cmd `sync` or `mkdir` (rootdir: %s, directory: %s)\n" %(X_rootdir, X_directory))
                continue
            if not a:
                write_std("# try to add path to file (exp: send filename)\n")
                continue
            r = sendFile(s, X_rootdir, X_directory, a, devid)
            continue
        if c == "write":
            if not X_rootdir or not X_directory:
                r = False
                write_std("# try to cmd `sync` or `mkdir` (rootdir: %s, directory: %s)\n" %(X_rootdir, X_directory))
                continue
            _d = mkdir(s, X_rootdir, X_prefix + "t")
            # вгружаем всё в текущей директории, кроме директорий и файлов с "."
            _sd = "/usr/src/debug"
            #_sd = "."
            for _n in [x for x in os.walk(_sd) if not x[0].startswith('./fcac_data')]:
                # создаём директорию
                _d = mkdir(s, X_rootdir, X_prefix + _n[0])
                if not _d:
                    r = False
                    break
                for _f in _n[2]:
                    _f = _n[0] + '/' + _f
                    if not sendFile(s, X_rootdir, _d, _f, devid):
                        _d = None
                        r = False
                        break
                if not _d or not r:
                    break

            continue
        if c == "read":
            if not X_rootdir:
                write_std("# try to cmd `sync` and `write` (rootdir: %s)\n" %(X_rootdir))
                r = False
                continue
            _file_readed = []
            for _n in [x for x in os.walk('.') if not x[0].startswith('./fcac_data')]:
                for _f in _n[2]:
                    _f = _n[0] + '/' + _f
                    _e = recvFileF(s, X_rootdir, _f, devid)
                    if not _e:
                        r = False
                        break
                    _file_readed.append(_e)
                if not r:
                    break
            continue
        if c == "store":
            _in_string = "The quick brown fox jumps over the lazy dog"
            msg_save = FEP.StoreSave()
            msg_save.id = random.randint(1, 10000)
            msg_save.shared = True
            msg_save.store = _in_string
            send_message(s, msg_save)
            rmsg = recv_message(s, ["Error", "Ok"])
            examine(rmsg)

            msg_load = FEP.StoreLoad()
            msg_load.id = random.randint(1, 10000)
            msg_load.shared = True
            send_message(s, msg_load)
            rmsg = recv_message(s, ["Error", "StoreValue"]);
            examine(rmsg)

            continue
        if c == "stress":
            for x in xrange(0, 10000):
                msg = FEP.Ping()
                msg.id = random.randint(1, 10000)
                msg.sec = 0
                msg.usec = 0
                send_message(s, msg)
                msg = FEP.WantSync()
                msg.id = random.randint(1, 10000)
                msg.checkpoint = 0
                msg.session_id = 1000000 + x
                send_message(s, msg)
                rmsg = recv_message(s, ("FileUpdate", "RootdirUpdate", "DirectoryUpdate", "Error", "Ok", "End", "State"))
                examine(rmsg)
            g = "ewait"
            continue
        if c == "sync":
            r = proto_sync(s)
            continue
        if c == "revision":
            if not X_rootdir or not _file_readed:
                write_std("no files readed, try cmd `read`: (rootdir: %s, files: %s)"
                        %(X_rootdir, len(_file_readed)))
                r = False
                continue
            for _f in _file_readed:
                for _r in _f[1:]:
                    if not updateRevision(s, X_rootdir, _f[0], _r[1], _r[0], _r[2], devid):
                        r = False
                        break
                if r is False:
                    break
            continue
        if c == "pdb":
            __import__("pdb").set_trace()

    return r

def connect(hosts, user, secret, devid, cmd = None):
    r =  False
    for host in hosts.split(','):
        write_std("# connect to %s, cmd: %s\n" %(host, str(cmd)))
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
                r = proto(sock, user, secret, devid, cmd)
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                write_std("# end connetion\n")
                return r
    write_std("# end of sockets\n")
    return r


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

def run(addr, user, secret, devid, cmd = None):
    thx = threading.Thread(None, thread_entry, "ServerWatch")
    thx.start()
    try:
        c = server_q.get()
        if c:
            connect(c, user, secret, devid, cmd)
    except KeyboardInterrupt:
        write_std("# interrupt\n")
    write_std("# exit\n")

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("use: %s <file|host[:port]> user secret device_id" %sys.argv[0])
        sys.exit(-1)
    addr = sys.argv[1]
    user = sys.argv[2]
    secret = sys.argv[3]
    devid = sys.argv[4]
    
    opts = sys.argv[5:]

    if not opts:
        opts = None

    if os.path.exists(addr):
        if not (os.path.isfile(addr) and os.access(addr, os.X_OK)):
            print("%s is not executable file", addr);
            sys.exit(-1)
        run(addr, user, secret, devid, opts)
    else:
        connect(addr, user, secret, devid, opts)

