#!/usr/bin/env python
# Copyright (c) 2012 Raffaele Sena http://www.aromatic.org/
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, dis-
# tribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the fol-
# lowing conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABIL-
# ITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS

#
# A simple shell to interact with DynamoDB
#

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

try:
    import cmd2 as cmd
except ImportError:
    import cmd

import ast
import boto
import boto.dynamodb.exceptions as dynamodb_exceptions
import json
import mimetypes
import logging
import os
import os.path
import pprint
import re
import readline
import shlex
import time
import traceback
import types

from os.path import basename

class DynamoDBShell(cmd.Cmd):

    prompt = "dynash> "

    def __init__(self):
        cmd.Cmd.__init__(self)

        self.pp = pprint.PrettyPrinter(indent=4)

        self.conn = boto.connect_dynamodb()

        # by default readline thinks - and other characters are word delimiters :(
        readline.set_completer_delims(re.sub('[-~]', '', readline.get_completer_delims()))
        self.tables = []
        self.table = None
        self.consistent = False
        self.print_time = False
        self.pretty_print = True
        self.verbose = False
        self.start_time = None

    def pprint(self, object):
        if self.pretty_print:
            print self.pp.pformat(object)
        else:
            print str(object)

    def getargs(self, line):
        return shlex.split(str(line.decode('string-escape')))

    def gettype(self, stype):
        return stype.upper()[0]

    def is_on(self, line):
        return line.lower() in [ 'yes', 'true', 'on', '1' ]

    def get_table_params(self, line):
        if line and line[0] == ':':
            parts = line.split(" ", 1)
            table_name = parts[0][1:]
            line = parts[1].strip() if len(parts) > 1 else ""
            return self.conn.get_table(table_name), line
        else:
            return self.table, line

    def get_table(self, line):
        if line:
            return self.conn.get_table(line)
        else:
            return self.table

    def do_tables(self, line):
        "List tables"
        self.tables = self.conn.list_tables()
        print "\nAvailable tables:"
        self.pprint(self.tables)

    def do_describe(self, line):
        "describe {tablename}"
        if line and line.startswith('-c'):
            create_info = True
            parts = line.split(" ", 1)
            line = parts[1].strip() if len(parts) > 1 else None
        else:
            create_info = False
            
        table = line or self.table.name
        desc = self.conn.describe_table(table)

        if create_info:
            info = desc['Table']
            schema = info['KeySchema']
            name = info['TableName']

            hkey = schema['HashKeyElement']
            hkey = "%s:%s" % (hkey['AttributeName'], hkey['AttributeType'])

            if 'RangeKeyElement' in schema:
                rkey = schema['RangeKeyElement']
                rkey = " %s:%s" % (rkey['AttributeName'], rkey['AttributeType'])
            else:
                rkey = ''

            prov = info['ProvisionedThroughput']
            prov = " -rc:%d -wc:%d" % (prov['ReadCapacityUnits'], prov['WriteCapacityUnits'])
            print "create %s %s%s" % ( name, hkey, rkey )
        else:
            self.pprint(desc)

    def do_use(self, line):
        "use {tablename}"
        self.table = self.conn.get_table_params(line)
        self.pprint(self.conn.describe_table(self.table.name))
        self.prompt = "%s> " % self.table.name

    def do_create(self, line):
        "create {tablename} {hkey}[:{type} {rkey}:{type}]"
        args = self.getargs(line)
        name = args[0]
        hkey = args[1]
        if ':' in hkey:
            hkey, hkey_type = hkey.split(':')
            hkey_type = self.gettype(hkey_type)
        else:
            hkey_type = self.gettype('S')
        if len(args) > 2:
            rkey = args[2]
            if ':' in rkey:
                rkey, rkey_type = rkey.split(':')
                rkey_type = self.gettype(rkey_type)
            else:
                rkey_type = self.gettype('S')
        else:
            rkey = rkey_type = None

        t = self.conn.create_table(name, 
            self.conn.create_schema(hkey, hkey_type, rkey, rkey_type),
            5, 5)
        self.pprint(self.conn.describe_table(t.name))

    def do_delete(self, line):
        "delete {tablename}"
        self.conn.delete_table(self.conn.get_table_params(line))

    def do_refresh(self, line):
        "refresh {table_name}"
        table = self.get_table(line)
        table.refresh(True)
        self.pprint(self.conn.describe_table(table.name))

    def do_capacity(self, line):
        "capacity {tablename} {read_units} {write_units}"
        args = self.getargs(line)

        table = self.get_table(args[0])
        read_units = int(args[1])
        write_units = int(args[2])

        table.update_throughput(read_units, write_units)
        print "capacity for %s updated to %d read units, %d write units" % (table.name, read_units, write_units)
        print ""
        self.do_refresh(table.name)


    def do_put(self, line):
        "put [:tablename] {json-body}"
        table, line = self.get_table_params(line)
        item = json.loads(line)
        table.new_item(None, None, item).put()

    def do_update(self, line):
        "update [:tablename] {hashkey} [-add|-delete] {attributes}"  # [ALL_OLD|ALL_NEW|UPDATED_OLD|UPDATED_NEW]"
        table, line = self.get_table_params(line)
        hkey, attr = line.split(" ", 1)

        if attr[0] == '-':
            op, attr = attr.split(" ", 1)
            op = op[1]
        else:
            op = "u"

        item = table.new_item(hash_key=hkey)

        attr = json.loads(attr.strip())
        for name in attr.keys():
            value = attr[name]
            if isinstance(value, list):
                value = set(value)

            if op == 'a':
                item.add_attribute(name, value)
            elif op == 'd':
                item.delete_attribute(name, value)
            else:
                item.put_attribute(name, value)

        self.pprint(item)
        updated = item.save(return_values='ALL_OLD')
        self.pprint(updated)

    def do_get(self, line):
        "get [:tablename] {haskkey} [rangekey]"
        table, line = self.get_table_params(line)

        if line.startswith('(') or line.startswith('[') or line.find(",") > 0:
            # list of IDs
            list = ast.literal_eval(line)
            print ">> get %s" % str(list)

            from collections import OrderedDict

            ordered = OrderedDict()
            for id in list:
                if not isinstance(id, tuple):
                    hkey = unicode(id)
                    rkey = None
                else:
                    hkey = unicode(id[0])
                    hkey = unicode(id[1])
                    
                ordered[(hkey, rkey)] = None

            batch = self.conn.new_batch_list()
            batch.add_batch(table, ordered.keys())
            response = batch.submit()

            hkey = table.schema.hash_key_name
            rkey = table.schema.range_key_name

            for item in response['Responses'][table.name]['Items']:
                ordered[(item.get(hkey),item.get(rkey))] = item

            self.pprint(filter(None, ordered.values()))
        else:
            args = self.getargs(line)
            hkey = args[0]
            rkey = args[1] if len(args) > 1 else None

            item = table.get_item(hkey, rkey,
                consistent_read=self.consistent)
            self.pprint(item)

    def do_rm(self, line):
        "rm [:tablename] {haskkey} [rangekey]"
        table, line = self.get_table_params(line)
        args = self.getargs(line)
        hkey = args[0]
        rkey = args[1] if len(args) > 1 else None
        item = table.get_item(hkey, rkey, [],
            consistent_read=self.consistent)
        if item:
            item.delete()

    def do_scan(self, line):
        "scan [:tablename] [attributes,...]"
        table, line = self.get_table_params(line)
        args = self.getargs(line)
        attrs = args[0].split(",") if args else None

        for item in table.scan(attributes_to_get=attrs):
            self.pprint(item)

    def do_query(self, line):
        "query [:tablename] hkey [attributes,...] [asc|desc]"
        table, line = self.get_table_params(line)
        args = self.getargs(line)

        if '-r' in args:
            asc = False
            args.remove('-r')
        else:
            asc = True
        
        hkey = args[0]
        attrs = args[1].split(",") if len(args) > 1 else None

        for item in table.query(hkey, attributes_to_get=attrs, scan_index_forward=asc):
            self.pprint(item)

    def do_rmall(self, line):
        "remove [tablename...] yes"
        args = self.getargs(line)
        if args and args[-1] == "yes":
            args.pop()

            if not args:
                args = [ self.table.name ]

            while args:
                table = self.conn.get_table_params(args.pop(0))
                print "from table " + table.name

                for item in table.scan(attributes_to_get=[]):
                    print "  removing %s" % item
                    item.delete()
        else:
            print "ok, never mind..."

    def do_elapsed(self, line):
        if line:
            self.print_time = self.is_on(line)

        print "print elapsed time: %s" % self.print_time

    def do_consistent(self, line):
        if line:
            self.consistent = self.is_on(line)

        print "use consistent reads: %s" % self.consistent

    def do_pretty(self, line):
        if line:
            self.pretty_print = self.is_on(line)

        print "pretty output: %s" % self.pretty_print

    def do_verbose(self, line):
        if line:
            self.verbose = self.is_on(line)

        print "verbose output: %s" % self.verbose
        if self.verbose:
            boto.set_stream_logger('boto', level=logging.DEBUG)
        else:
            boto.set_stream_logger('boto', level=logging.INFO)

    def do_EOF(self, line):
        "Exit shell"
        return True

    def do_shell(self, line):
        "Shell"
        os.system(line)

    do_ls = do_tables
    do_mkdir = do_create
    do_rmdir = do_delete
    do_cd = do_use
    do_q = do_query
    do_l = do_scan
    do_exit = do_quit = do_EOF

    #
    # override cmd
    #

    def emptyline(self):
        pass

    def onecmd(self, s):
        try:
            return cmd.Cmd.onecmd(self, s)
        except IndexError:
            print "invalid number of arguments"
            return False
        except dynamodb_exceptions.DynamoDBResponseError, dberror:
            print self.pp.pformat(dberror)
        except:
            traceback.print_exc()
            return False

    def completedefault(self, test, line, beginidx, endidx):
        list=[]

        for t in self.tables:
            if t.startswith(test):
                list.append(t)

        return list

    def preloop(self):
        print "\nA simple shell to interact with DynamoDB"
        try:
            self.do_tables('')
        except:
            traceback.print_exc()

    def postloop(self):
        print "Goodbye!"

    def precmd(self, line):
        if self.print_time:
            self.start_time = time.time()
        else:
            self.start_time = None
        return line

    def postcmd(self, stop, line):
        if self.start_time:
            t = time.time() - self.start_time
            print "elapsed time: %.3f" % t
        return stop



if __name__ == '__main__':
    DynamoDBShell().cmdloop()
