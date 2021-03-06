#!/usr/bin/env python
# -*- encoding: utf-8 -*
# vim: ft=python ff=unix fenc=utf-8
# file: unit_all_test.py

import unittest
import psycopg2
import random
import proto

import ConfigParser as configparser
import StringIO

def gen_char(n):
    s = 'qwertyuiopasdfghjklzxcvbnm'
    return ''.join(random.choice(s) for i in range(n))

class TestSetUper():
    username = gen_char(3)
    secret = gen_char(6)
    host = "localhost:5151"
    pgstring = "dbname = fepserver"
    devid = random.randint(0, 1 << 32)
    
    def setUp(self):
        p = configparser.ConfigParser()
        # получение конфигурации сервера
        with open("bin/server.conf") as xf:
            _l = StringIO.StringIO("[xxx]\n" + xf.read())
            p.readfp(_l)
        
        try: self.pgstring = p.get("xxx", "pg_connstr").replace("\"", "")
        except: pass
        try: self.host = p.get("xxx", "bind").replace("\"", "")
        except: pass

        # добавление пользователя в бд
        con = psycopg2.connect(self.pgstring)
        cur = con.cursor()
        cur.execute("INSERT INTO \"user\" (username, secret) SELECT %s, %s WHERE NOT EXISTS (SELECT * FROM \"user\" WHERE username = %s)",
                (self.username, self.secret, self.username))
        cur.close()
        con.commit()
        con.close()

        #
        print("userinfo: %s:%s (%s)" %(self.username, self.secret, self.devid))

class ReadWriteTests(TestSetUper, unittest.TestCase):

    def test_1_mkdir(self):
        # создание и удаление директории в первой попавшейся рутдире
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "rmdir"]), True)
   
    def test_2_WriteRead(self):
        # загрузка всех файлов и каталогов в текущей директории и чтение их же
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "write", "read"]), True)

    def test_3_revision(self):
        # проверка на обновление ревизий
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "read", "revision"]), True)

    def test_4_rmdir(self):
        # проверка удаления всех накачанных файлов 
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "rmdir"]), True)

    def test_5_remove(self):
        # перегенарация devid, что бы избежать наложения uuid файлов
        self.devid = random.randint(0, 1 << 32)
        # последовательная загрузка, удаление и попытка чтения файлов
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "write", "remove"]), True)
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "read"]), False)

if __name__ == '__main__':
    unittest.main()

