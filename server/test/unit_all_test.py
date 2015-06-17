#!/usr/bin/env python
# -*- encoding: utf-8 -*
# vim: ft=python ff=unix fenc=utf-8
# file: unit_all_test.py

import unittest
import psycopg2
import random
import proto

def gen_char(n):
    s = 'qwertyuiopasdfghjklzxcvbnm'
    return ''.join(random.choice(s) for i in range(n))

class TestSetUper():
    username = gen_char(3)
    secret = gen_char(6)
    host = "localhost:5151"
    devid = random.randint(0, 1 << 32)
    
    def setUp(self):
        # добавление пользователя в бд
        con = psycopg2.connect("dbname=fepserver")
        cur = con.cursor()
        cur.execute("INSERT INTO \"user\" (username, secret) SELECT %s, %s WHERE NOT EXISTS (SELECT * FROM \"user\" WHERE username = %s)",
                (self.username, self.secret, self.username))
        cur.close()
        con.commit()
        con.close()

        #
        print("userinfo: %s:%s (%s)" %(self.username, self.secret, self.devid))

class ReadWriteTests(TestSetUper, unittest.TestCase):

    def test_mkdir(self):
        # создание и удаление директории в первой попавшейся рутдире
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "rmdir"]), True)
   
    def test_WriteRead(self):
        # загрузка всех файлов и каталогов в текущей директории и чтение их же
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "write", "read"]), True)
    
    def test_rmdir(self):
        # проверка удаления всех накачанных файлов 
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "rmdir"]), True)

if __name__ == '__main__':
    unittest.main()

