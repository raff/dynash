#!/usr/bin/env python
# Copyright (c) 2012 Raffaele Sena https://github.com/raff
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

from version import __version__

from cmd2 import Cmd

import boto
from boto.dynamodb.exceptions import DynamoDBResponseError, DynamoDBConditionalCheckFailedError, BotoClientError
from boto.dynamodb.condition import *
from boto.dynamodb.types import Binary

import ast
import json
import logging
import os
import os.path
import pprint
import re
import shlex
import sys
import traceback


try:
    import readline
except ImportError:
    try:
        import pyreadline as readline
    except ImportError:
        readline = None
else:
    import rlcompleter
    if(sys.platform == 'darwin'):
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")


##########################################
#
# Monkey patch boto to support count results
#

from boto.dynamodb import layer2


class TableGenerator(layer2.TableGenerator):

    def __init__(self, table, callable, max_results, item_class, kwargs):
        _original_TableGenerator.__init__(self, table, callable, max_results, item_class, kwargs)

        if 'count' in kwargs and kwargs['count']:
            self.count = 0
            self.scanned_count = 0
            self.consumed_units = 0

            response = True
            while response:
                response = self.callable(**self.kwargs)

                if 'ConsumedCapacityUnits' in response:
                    self.consumed_units += response['ConsumedCapacityUnits']

                if 'Count' in response:
                    self.count += response['Count']

                if 'ScannedCount' in response:
                    self.scanned_count += response['ScannedCount']

                if 'LastEvaluatedKey' in response:
                    lek = response['LastEvaluatedKey']
                    esk = self.table.layer2.dynamize_last_evaluated_key(lek)
                    self.kwargs['exclusive_start_key'] = esk
                else:
                    break

_original_TableGenerator = layer2.TableGenerator
layer2.TableGenerator = TableGenerator

#
##########################################

HISTORY_FILE = ".dynash_history"


class DynamoDBShell(Cmd):

    prompt = "dynash> "

    consistent = False
    consumed = False  # this should really be print_consumed
    pretty = True
    verbose = False

    settable = Cmd.settable + """
        consistent consistent reads vs. eventual consistency
        consumed print consumed units
        prompt command prompt
        pretty pretty-print results
        verbose verbose logging of boto requests
        """

    def _onchange_verbose(self, old, new):
        if new:
            boto.set_stream_logger('boto', level=logging.DEBUG)
        else:
            boto.set_stream_logger('boto', level=logging.WARNING)

    def __init__(self):
        Cmd.__init__(self)

        self.pp = pprint.PrettyPrinter(indent=4)

        self.conn = boto.connect_dynamodb()

        # by default readline thinks - and other characters are word delimiters :(
        if readline:
            readline.set_completer_delims(re.sub('[-~]', '', readline.get_completer_delims()))

            path = os.path.join(os.environ.get('HOME', ''), HISTORY_FILE)
            self.history_file = os.path.abspath(path)
        else:
            self.history_file = None

        self.tables = []
        self.table = None
        self.consistent = False
        self.consumed = False
        self.verbose = False

    def pprint(self, object):
        if self.pretty:
            print self.pp.pformat(object)
        else:
            print str(object)

    def print_iterator(self, gen):
        prev = None
        print "["

        for next in gen:
            if prev:
                print "  %s," % prev
            prev = next

        if prev:
            print "  %s" % prev

        print "]"

    def getargs(self, line):
        return shlex.split(str(line.decode('string-escape')))

    def get_type(self, stype):
        if stype == 'S':
            return "S"

        if stype == 'N':
            return 1

        if stype == 'B':
            return Binary('B')

        # those are not valid key types, but anyway

        if stype == 'SS':
            return {"S"}

        if stype == 'NS':
            return {1}
        return None

    def get_first_rest(self, line):
        param, _, rest = line.partition(" ")
        return param, rest.strip()

    def get_table_params(self, line):
        if line and line[0] == ':':
            table_name, line = self.get_first_rest(line)
            return self.conn.get_table(table_name[1:]), line
        else:
            return self.table, line

    def get_table(self, line):
        if line:
            return self.conn.get_table(line)
        else:
            return self.table

    def get_typed_value(self, table, value, is_hash=True):
        schema = table.schema

        keytype = schema.hash_key_type if is_hash else schema.range_key_type
        if not keytype:
            return value

        try:
            if keytype == 'S':
                return str(value)
            if keytype == 'N':
                return float(value) if '.' in value else int(value)
        except:
            pass

        return value

    def get_list(self, line):
        try:
            return json.loads(line)
        except:
            return ast.literal_eval(line)

    def get_expected(self, line):
        expected = {}

        while line.startswith("!"):
            # !field:expected-value
            param, line = self.get_first_rest(line[1:])
            name, value = param.split(":", 1)
            expected[name] = value or False

        return expected or None, line

    def do_login(self, line):
        "login aws-acces-key aws-secret"
        if line:
            args = self.getargs(line)

            self.conn = boto.connect_dynamodb(
                aws_access_key_id=args[0],
                aws_secret_access_key=args[1])
        else:
            self.conn = boto.connect_dynamodb()

        self.do_tables('')

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
            prov = "-c %d,%d" % (prov['ReadCapacityUnits'], prov['WriteCapacityUnits'])
            print "create %s %s %s%s" % (name, prov, hkey, rkey)
        else:
            self.pprint(desc)

    def do_use(self, line):
        "use {tablename}"
        self.table = self.conn.get_table(line)
        self.pprint(self.conn.describe_table(self.table.name))
        self.prompt = "%s> " % self.table.name

    def do_create(self, line):
        "create {tablename} [-c rc,wc] {hkey}[:{type} {rkey}:{type}]"
        args = self.getargs(line)
        rc = wc = 5

        name = args.pop(0)  #  tablename

        if args[0] == "-c": # capacity
            args.pop(0)  # skyp -c

            capacity = args.pop(0).strip()
            rc, _, wc = capacity.partition(",")
            rc = int(rc)
            wc = int(wc) if wc != "" else rc

        hkey, _, hkey_type = args.pop(0).partition(':')
        hkey_type = self.get_type(hkey_type or 'S')

        if args:
            rkey, _, rkey_type = args.pop(0).partition(':')
            rkey_type = self.get_type(rkey_type or 'S')
        else:
            rkey = rkey_type = None

        t = self.conn.create_table(name,
                                   self.conn.create_schema(hkey, hkey_type, rkey, rkey_type),
                                   rc, wc)
        self.pprint(self.conn.describe_table(t.name))

    def do_drop(self, line):
        "drop {tablename}"
        self.conn.delete_table(self.conn.get_table(line))

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

        desc = self.conn.describe_table(table.name)
        prov = desc['Table']['ProvisionedThroughput']

        current_read, current_write = prov['ReadCapacityUnits'], prov['WriteCapacityUnits']
        if read_units < current_read or write_units < current_write:
            table.update_throughput(read_units, write_units)
            print "%s: updating capacity to %d read units, %d write units" % (table.name, read_units, write_units)
            print ""
            self.do_refresh(table.name)

        else:
            print "%s: current capacity is %d read units, %d write units" % (table.name, current_read, current_write)
            # we can only double the current value at each call
            while current_read < read_units and current_write < write_units:
                if (read_units - current_read) > current_read:
                    current_read *= 2
                else:
                    current_read = read_units

                if (write_units - current_write) > current_write:
                    current_write *= 2
                else:
                    current_write = write_units

                print "%s: updating capacity to %d read units, %d write units" % (table.name, current_read, current_write)
                table.update_throughput(current_read, current_write)

                print ""
                self.do_refresh(table.name)
                print ""

    def do_put(self, line):
        "put [:tablename] [!fieldname:expectedvalue] {json-body} [{json-body}, {json-body}...]"
        table, line = self.get_table_params(line)
        expected, line = self.get_expected(line)

        if line.startswith('(') or line.startswith('['):
            list = self.get_list(line)
            wlist = self.conn.new_batch_write_list()
            wlist.add_batch(table, [ table.new_item(None, None, item) for item in list ])
            response = self.conn.batch_write_item(wlist)
            consumed = response['Responses'][table.name]['ConsumedCapacityUnits']

            if 'UnprocessedItems' in response and response['UnprocessedItems']:
                print ""
                print "unprocessed: ", response['UnprocessedItems']
                print ""
        else:
            item = json.loads(line)
            table.new_item(None, None, item).put(expected_value=expected)
            consumed = None

        if self.consumed and consumed:
            print "consumed units:", consumed

    def do_import(self, line):
        "import [:tablename] filename|list"
        table, line = self.get_table_params(line)
        if line[0] == '[':
            list = self.get_list(line)
        else:
            with open(line) as f:
                list = self.get_list(f.read())

        items = 0
        consumed = 0

        for item in list:
            table.new_item(None, None, item).put()
            #consumed += item.consumed_units
            items += 1
            print item['id']

        print "imported %s items, consumed units:%s" % (items, consumed)

    def do_update(self, line):
        "update [:tablename] {hashkey[,rangekey]} [!fieldname:expectedvalue] [-add|-delete] [+ALL_OLD|ALL_NEW|UPDATED_OLD|UPDATED_NEW] {attributes}" 
        table, line = self.get_table_params(line)
        hkey, line = line.split(" ", 1)
        expected, attr = self.get_expected(line)

        if attr[0] == '-':
            op, attr = attr.split(" ", 1)
            op = op[1]
        else:
            op = "u"

        if attr[0] == '+':
            ret, attr = attr.split(" ", 1)
            ret = ret[1:]
        else:
            ret = "ALL_NEW"

        if ',' in hkey:
            hkey, rkey = hkey.split(",", 1)
        else:
            rkey = None

        item = table.new_item(hash_key=self.get_typed_value(table, hkey), range_key=self.get_typed_value(table, rkey, False))

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
        updated = item.save(expected_value=expected or None, return_values=ret)
        self.pprint(updated)

        if self.consumed:
            print "consumed units:", item.consumed_units

    def do_get(self, line):
        """
        get [:tablename] {haskkey} [rangekey]
        or
        get [:tablename] ((hkey,rkey), (hkey,rkey)...)

        """

        table, line = self.get_table_params(line)

        if line.startswith('(') or line.startswith('[') or "," in line:
            # list of IDs
            list = self.get_list(line)

            from collections import OrderedDict

            ordered = OrderedDict()
            for id in list:
                if not isinstance(id, tuple):
                    hkey = self.get_typed_value(table, unicode(id))
                    rkey = None
                else:
                    hkey = self.get_typed_value(table, unicode(id[0]), True)
                    rkey = self.get_typed_value(table, unicode(id[1]), False)

                ordered[(hkey, rkey)] = None

            batch = self.conn.new_batch_list()
            batch.add_batch(table, ordered.keys())
            response = batch.submit()

            hkey = table.schema.hash_key_name
            rkey = table.schema.range_key_name

            for item in response['Responses'][table.name]['Items']:
                ordered[(item.get(hkey), item.get(rkey))] = item

            self.pprint(filter(None, ordered.values()))
        else:
            args = self.getargs(line)
            hkey = self.get_typed_value(table, args[0], True)
            rkey = self.get_typed_value(table, args[1], False) if len(args) > 1 else None

            item = table.get_item(hkey, rkey,
                                  consistent_read=self.consistent)
            self.pprint(item)

            if self.consumed:
                print "consumed units:", item.consumed_units

    def do_rm(self, line):
        "rm [:tablename] [!fieldname:expectedvalue] [-v] {haskkey,[rangekey]}"
        table, line = self.get_table_params(line)
        expected, line = self.get_expected(line)
        
        if line.startswith("-v "):
            line = line[3:].strip()
            ret = "ALL_OLD"
        else:
            ret = None

        hkey = line
        if ',' in hkey:
            hkey, rkey = hkey.split(",", 1)
        else:
            rkey = None

        item = table.new_item(hash_key=self.get_typed_value(table, hkey), range_key=self.get_typed_value(table, rkey, False))
        item = item.delete(expected_value=expected, return_values=ret)
        self.pprint(item)

        if self.consumed:
            print "consumed units:", item.consumed_units

    def do_scan(self, line):
        "scan [:tablename] [-{max}] [+filter_attribute:filter_value] [attributes,...]"
        table, line = self.get_table_params(line)
        args = self.getargs(line)

        scan_filter = {}
        count = False
        max = None

        while args:
            if args[0].startswith('+'):
                arg = args.pop(0)
                filter = arg[1:].split(':', 1)
                scan_filter[filter[0]] = EQ(filter[1])

            elif args[0].startswith('-'):
                arg = args.pop(0)

                if arg == '-c':
                    count = True

                elif arg[0] == '-' and arg[1:].isdigit():
                    max = arg[1:]

                elif arg == '--':
                    break

                else:
                    print "invalid argument: %s" % arg
                    break

            else:
                break

        #if scan_filter:
        #    print scan_filter

        attrs = args[0].split(",") if args else None

        result = table.scan(scan_filter=scan_filter, attributes_to_get=attrs, max_results=max, count=count)

        if count:
            print "count: %s/%s" % (result.scanned_count, result.count)
        else:
            self.print_iterator(result)

        if self.consumed:
            print "consumed units:", result.consumed_units

    def do_query(self, line):
        "query [:tablename] [-r] [-{max}] hkey [attributes,...]"
        table, line = self.get_table_params(line)
        args = self.getargs(line)

        max = None
        condition = None

        if '-r' in args:
            asc = False
            args.remove('-r')
        else:
            asc = True

        while args:
            arg = args[0]

            if arg[0] == '-' and arg[1:].isdigit():
                max = int(arg[1:])
                args.pop(0)
            
            elif arg.startswith("--begin=") or arg.startswith("--start="):
                condition = BEGINS_WITH(self.get_typed_value(table, arg[8:], True))
                args.pop(0)
            elif arg.startswith("--eq="):
                condition = EQ(self.get_typed_value(table, arg[5:], True))
                args.pop(0)
            elif arg.startswith("--le="):
                condition = LE(self.get_typed_value(table, arg[5:], True))
                args.pop(0)
            elif arg.startswith("--lt="):
                condition = LT(self.get_typed_value(table, arg[5:], True))
                args.pop(0)
            elif arg.startswith("--ge="):
                condition = LE(self.get_typed_value(table, arg[5:], True))
                args.pop(0)
            elif arg.startswith("--gt="):
                condition = LT(self.get_typed_value(table, arg[5:], True))
                args.pop(0)
            elif arg.startswith("--between="):
                parts = arg[10:].split(",", 1)
                condition = BETWEEN(self.get_typed_value(table, parts[0], True), self.get_typed_value(table, parts[1], True))
                args.pop(0)

            else:
                break

        hkey = self.get_typed_value(table, args[0])
        attrs = args[1].split(",") if len(args) > 1 else None

        result = table.query(hkey, range_key_condition=condition, attributes_to_get=attrs, scan_index_forward=asc, max_results=max)

        self.print_iterator(result)

        if self.consumed:
            print "consumed units:", result.consumed_units

    def do_rmall(self, line):
        "remove [tablename...] yes"
        args = self.getargs(line)
        if args and args[-1] == "yes":
            args.pop()

            if not args:
                args = [self.table.name]

            while args:
                table = self.conn.get_table(args.pop(0))
                print "from table " + table.name

                for item in table.scan(attributes_to_get=[]):
                    print "  removing %s" % item
                    item.delete()
        else:
            print "ok, never mind..."

    def do_EOF(self, line):
        "Exit shell"
        return True

    do_ls = do_tables
    do_mkdir = do_create
    do_rmdir = do_drop
    do_delete = do_drop
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
            return Cmd.onecmd(self, s)
        except IndexError:
            print "invalid number of arguments"
            return False
        except NotImplementedError as e:
            print e.message
        except DynamoDBConditionalCheckFailedError as e:
            print e.error_message
        except (DynamoDBResponseError, BotoClientError) as dberror:
            print self.pp.pformat(dberror)
        except:
            traceback.print_exc()
        return False

    def default(self, line):
        line = line.strip()
        if line and line[0] in ['#', ';']:
            return False
        else:
            return Cmd.default(self, line)

    def completedefault(self, test, line, beginidx, endidx):
        list = []

        for t in self.tables:
            if t.startswith(test):
                list.append(t)

        return list

    def preloop(self):
        print "\ndynash %s: A simple shell to interact with DynamoDB" % __version__

        if self.history_file and os.path.exists(self.history_file):
            readline.read_history_file(self.history_file)

        try:
            self.do_tables('')
        except:
            traceback.print_exc()

    def postloop(self):
        if self.history_file:
            readline.set_history_length(100)
            readline.write_history_file(self.history_file)

        print "Goodbye!"


def run_command():
    DynamoDBShell().cmdloop()


if __name__ == '__main__':
    run_command()
