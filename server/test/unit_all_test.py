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


class BasicTests(unittest.TestCase):
    def setUp(self):
        self.username = gen_char(3)
        self.secret = gen_char(6)
        self.host = "localhost:5151"
        self.devid = random.randint(0, 1 << 32)
        
        # добавление пользователя в бд
        con = psycopg2.connect("dbname=fepserver")
        cur = con.cursor()
        cur.execute("INSERT INTO \"user\" (username, secret) VALUES (%s, %s);",
                (self.username, self.secret))
        cur.close()
        con.commit()
        con.close()

        #
        print("userinfo: %s:%s (%s)" %(self.username, self.secret, self.devid))

    def test_mkdir(self):
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "rmdir"]), True)
   
    def test_write(self):
        self.assertEqual(proto.connect(self.host, self.username, self.secret, self.devid, ["sync", "mkdir", "write"]), True)


if __name__ == '__main__':
    unittest.main()
