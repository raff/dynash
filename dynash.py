#!/usr/bin/env python

# Make all string literals unicode
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import boto
import cmd
import json
import mimetypes
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
        self.start_time = None

    def getargs(self, line):
        return shlex.split(line)

    def gettype(self, stype):
        return stype.upper()[0]

    def do_tables(self, line):
        "List tables"
        print "\nAvaliable tables:"
        self.tables = self.conn.list_tables()
        self.pp.pprint(self.tables)

    def do_describe(self, line):
        "Describe table"
        if line:
            self.pp.pprint(self.conn.describe_table(line))
        elif self.table:
            self.pp.pprint(self.conn.describe_table(self.table.name))

    def do_use(self, line):
        "Select table"
        self.table = self.conn.get_table(line)
        self.pp.pprint(self.conn.describe_table(self.table.name))
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
        self.pp.pprint(self.conn.describe_table(t.name))

    def do_delete(self, line):
        "delete {tablename}"
        self.conn.delete_table(self.conn.get_table(line))

    def do_refresh(self, line):
        if line:
            table = self.conn.get_table(line)
        else:
            table = self.table
        table.refresh(True)
        self.pp.pprint(self.conn.describe_table(table.name))

    def do_put(self, line):
        "put {json-body}"
        item = json.loads(line)
        self.table.new_item(None, None, item).put()

    def do_update(self, line):
        "update {hashkey} {attributes} [ALL_OLD|ALL_NEW|UPDATED_OLD|UPDATED_NEW]"
        hkey, attr = line.split(" ", 1)
        attr = json.loads(attr.strip())
        item = self.table.new_item(hash_key=hkey)
        for name in attr.keys():
            value = attr[name]
            if isinstance(value, list):
                value = set(value)
            item[name] = value

        self.pp.pprint(item)
        updated = item.save(return_values='ALL_OLD')
        self.pp.pprint(updated)

    def do_get(self, line):
        "get {haskkey} [rangekey]"
        args = self.getargs(line)
        hkey = args[0]
        rkey = args[1] if len(args) > 1 else None
        #self.pp.pprint(self.table.get_item(hkey, rkey))

        item = self.table.get_item(hkey, rkey,
            consistent_read=self.consistent)
        self.pp.pprint(item)

    def do_rm(self, line):
        "rm {haskkey} [rangekey]"
        args = self.getargs(line)
        hkey = args[0]
        rkey = args[1] if len(args) > 1 else None
        item = self.table.get_item(hkey, rkey, [],
            consistent_read=self.consistent)
        if item:
            item.delete()

    def do_all(self, line):
        "get all entries"
        args = self.getargs(line)
        if args and args[0] != '.':
            table = self.conn.get_table(args[0])
        else:
            table = self.table
        attrs = args[1].split(",") if len(args) > 1 else None
        for item in table.scan(attributes_to_get=attrs):
            self.pp.pprint(item)

    def do_rmall(self, line):
        "remove all entries in table (say 'yes')"
        args = self.getargs(line)
        if args and args[-1] == "yes":
            args.pop()

            if not args:
                args = [ self.table.name ]

            while args:
                table = self.conn.get_table(args.pop())
                print "from table " + table.name

                for item in table.scan(attributes_to_get=[]):
                    print "  removing %s" % item
                    item.delete()
        else:
            print "ok, never mind..."

    def do_elapsed(self, line):
        if line:
            self.print_time = line in [ 'yes', 'true', '1' ]
        else:
            self.print_time = not self.print_time
        print "print elapsed time: %s" % self.print_time

    def do_consistent(self, line):
        if line:
            self.consistent = line in [ 'yes', 'true', '1' ]
        else:
            self.consistent = not self.consistent
        print "use consistent reads: %s" % self.consistent

    def do_EOF(self, line):
        "Exit shell"
        return True

    def do_shell(self, line):
        "Shell"
        os.system(line)

    do_ls = do_tables
    do_mkdir = do_create
    do_rmdir = do_delete
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
        self.do_tables('')

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
