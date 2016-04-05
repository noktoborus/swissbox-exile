#!/bin/sh
# vim: ft=sh ff=unix fenc=utf-8
# file: rm.sh

rm -rf fcac_data/*
psql <sql/struct.sql
echo "INSERT INTO \"user\" (username, secret) VALUES ('test1', 'bond');" | psql
