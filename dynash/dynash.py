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
import csv
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
    #if(sys.platform == 'darwin'):
    #    readline.parse_and_bind("bind ^I rl_complete")
    #else:
    #    readline.parse_and_bind("tab: complete")
    readline.parse_and_bind("tab: complete")

HISTORY_FILE = ".dynash_history"
VALID_TYPES = set(['S', 'N', 'B', 'SS', 'NS'])


class DynamoEncoder(json.JSONEncoder):
    """
    This is mainly used to transform sets to lists
    """
    def default(self, o):
        try:
            iterable = iter(o)
        except TypeError:
            pass
        else:
            return list(iterable)

        return JSONEncoder.default(self, o)


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

    def __init__(self, verbose=False):
        Cmd.__init__(self)

        self.pp = pprint.PrettyPrinter(indent=4)

        try:
            self.conn = boto.connect_dynamodb()
        except Exception as e:
            self.conn = None
            print e
            print "Cannot connect to dynamodb - Check your credentials in ~/.boto or use the 'login' command"

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
        self.verbose = verbose
        self.next_key = None
        self.schema = {}

        if verbose:
            self._onchange_verbose(None, verbose)

    def pprint(self, object, prefix=''):
        print "%s%s" % (prefix, self.pp.pformat(object) if self.pretty else str(object))

    def print_iterator(self, gen):
        encoder = DynamoEncoder()

        prev_item = None
        print "["

        for next_item in gen:
            if prev_item:
                print "  %s," % encoder.encode(prev_item)
            prev_item = next_item

        if prev_item:
            print "  %s" % encoder.encode(prev_item)

        print "]"

    def print_iterator_array(self, gen, keys):
        writer = csv.writer(sys.stdout, quoting=csv.QUOTE_MINIMAL, doublequote=False, escapechar=str('\\'))

        def to_array(item):
            return [item.get(k) for k in keys]

        def value(v):
            if isinstance(v, basestring):
                return v.encode("utf-8")
            return v

        for item in gen:
            writer.writerow([value(v) for v in to_array(item)])

    def getargs(self, line):
        return shlex.split(str(line.decode('unicode-escape')))

    def get_type(self, stype):
        if stype == 'S':
            return "S"

        if stype == 'N':
            return 1

        if stype == 'B':
            return Binary('B')

        # those are not valid key types, but anyway

        if stype == 'SS':
            return set(["S"])

        if stype == 'NS':
            return set([1])
        return None

    def get_first_rest(self, line):
        param, _, rest = line.partition(" ")
        return param, rest.strip()

    def get_table_params(self, line):
        if line and (line[0] == ':' or not self.table):
            table_name, line = self.get_first_rest(line)
            return self.conn.get_table(table_name.lstrip(':')), line
        else:
            return self.table, line

    def get_table(self, line):
        if line:
            return self.conn.get_table(line)
        else:
            return self.table

    def get_typed_key_value(self, table, value, is_hash=True):
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

    def get_typed_value(self, field, value):
        ftype = self.schema.get(field)
        if not ftype:
            return value

        try:
            if ftype == 'S':
                return str(value)
            if ftype == 'N':
                return float(value) if '.' in value else int(value)

            print "type %s is not supported yet" % ftype
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

    def do_env(self, line):
        """
        env {environment-name}
        """
        if not line:
            print "use: env {environment-name}"
        else:
            if not set_environment(line):
                print "no configuration for environment %s" % line
            else:
                self.do_login('')

    def do_schema(self, line):
        """
        schema

        schema --clear

        schema filed_name field_type
        """
        args = self.getargs(line)

        if not args:
            for k in sorted(self.schema):
                print "%s\t%s" % (k, self.schema[k])
        elif args[0] == "--clear":
            self.schema.clear()
        else:
            fname = args[0]
            ftype = args[1]

            if not ftype in VALID_TYPES:
                print "invalid type: use %s" % list(VALID_TYPES)
            else:
                self.schema[fname] = ftype

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
        "describe [-c] {tablename}..."
        args = self.getargs(line)

        if '-c' in args:
            create_info = True
            args.remove('-c')
        else:
            create_info = False

        if not args:
            if self.table:
                args = [self.table.name]
            else:
                args = self.tables

        for table in args:
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
                self.pprint(desc, "%s: " % table)

    def do_use(self, line):
        "use {tablename}"
        self.table = self.conn.get_table(line)
        self.pprint(self.conn.describe_table(self.table.name))
        self.prompt = "%s> " % self.table.name

    def do_create(self, line):
        "create {tablename} [-c rc,wc] {hkey}[:{type} {rkey}:{type}]"
        args = self.getargs(line)
        rc = wc = 5

        name = args.pop(0)  # tablename

        if args[0] == "-c":  # capacity
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
            while current_read < read_units or current_write < write_units:
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
            wlist.add_batch(table, [table.new_item(None, None, item) for item in list])
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

        item = table.new_item(hash_key=self.get_typed_key_value(table, hkey), range_key=self.get_typed_key_value(table, rkey, False))

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
                    hkey = self.get_typed_key_value(table, unicode(id))
                    rkey = None
                else:
                    hkey = self.get_typed_key_value(table, unicode(id[0]), True)
                    rkey = self.get_typed_key_value(table, unicode(id[1]), False)

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
            hkey = self.get_typed_key_value(table, args[0], True)
            rkey = self.get_typed_key_value(table, args[1], False) if len(args) > 1 else None

            item = table.get_item(hkey, rkey,
                                  consistent_read=self.consistent)
            self.pprint(item)

            if self.consumed:
                print "consumed units:", item.consumed_units

    def do_rm(self, line):
        "rm [:tablename] [!fieldname:expectedvalue] [-v] {haskkey [rangekey]}"
        table, line = self.get_table_params(line)
        expected, line = self.get_expected(line)

        args = self.getargs(line)

        if "-v" in args:
            ret = "ALL_OLD"
            args.remove("-v")
        else:
            ret = None

        hkey = self.get_typed_key_value(table, args[0], True)
        rkey = self.get_typed_key_value(table, args[1], False) if len(args) > 1 else None

        item = table.new_item(hash_key=hkey, range_key=rkey)
        item = item.delete(expected_value=expected, return_values=ret)
        self.pprint(item)

        if self.consumed:
            print "consumed units:", item.consumed_units

    def do_rmattr(self, line):
        "rmattr [:tablename] [!fieldname:expectedvalue] [-v] {haskkey,[rangekey]} attr [attr...]"
        table, line = self.get_table_params(line)
        expected, line = self.get_expected(line)

        args = self.getargs(line)

        if "-v" in args:
            ret = "ALL_OLD"
            args.remove("-v")
        else:
            ret = None

        hkey = self.get_typed_key_value(table, args[0], True)
        rkey = self.get_typed_key_value(table, args[1], False) if len(args) > 1 else None

        item = table.new_item(hash_key=hkey, range_key=rkey)

        for arg in args:
            item.delete_attribute(arg)

        item = item.save(expected_value=expected, return_values=ret)
        self.pprint(item)

        if self.consumed:
            print "consumed units:", item.consumed_units

    def do_scan(self, line):
        """
        scan [:tablename] [--batch=#] [-{max}] [--count|-c] [--array|-a] [+filter_attribute:filter_value] [attributes,...]

        if filter_value contains '=' it's interpreted as {conditional}={value} where condtional is:

            eq (equal value)
            ne {value} (not equal value)
            le (less or equal then value)
            lt (less then value)
            ge (greater or equal then value)
            gt (greater then value)
            :exists (value exists)
            :nexists (value does not exists)
            contains (contains value)
            ncontains (does not contains value)
            begin (attribute begins with value)
            between (between value1 and value2 - use: between=value1,value2)

        otherwise the value must fully match (equal attribute)
        """

        table, line = self.get_table_params(line)
        args = self.getargs(line)

        scan_filter = {}
        count = False
        as_array = False
        max_size = None
        batch_size = None
        start = None

        while args:
            arg = args[0]

            if arg.startswith('+'):
                args.pop(0)
                filter_name, filter_value = arg[1:].split(':', 1)

                if filter_value.startswith("begin="):
                    filter_cond = BEGINS_WITH(self.get_typed_value(filter_name, filter_value[6:]))
                elif filter_value.startswith("eq="):
                    filter_cond = EQ(self.get_typed_value(filter_name, filter_value[3:]))
                elif filter_value.startswith("ne="):
                    filter_cond = NE(self.get_typed_value(filter_name, filter_value[3:]))
                elif filter_value.startswith("le="):
                    filter_cond = LE(self.get_typed_value(filter_name, filter_value[3:]))
                elif filter_value.startswith("lt="):
                    filter_cond = LT(self.get_typed_value(filter_name, filter_value[3:]))
                elif filter_value.startswith("ge="):
                    filter_cond = GE(self.get_typed_value(filter_name, filter_value[3:]))
                elif filter_value.startswith("gt="):
                    filter_cond = GT(self.get_typed_value(filter_name, filter_value[3:]))
                elif filter_value == ":exists":
                    filter_cond = NOT_NULL()
                elif filter_value == ":nexists":
                    filter_cond = NULL()
                elif filter_value.startswith("contains="):
                    filter_cond = CONTAINS(self.get_typed_value(filter_name, filter_value[9:]))
                elif filter_value.startswith("between="):
                    parts = filter_value[8:].split(",", 1)
                    filter_cond = BETWEEN(self.get_typed_value(parts[0]), self.get_typed_value(filter_name, parts[1]))
                else:
                    filter_cond = EQ(self.get_typed_value(filter_name, filter_value))

                scan_filter[filter_name] = filter_cond

            elif arg.startswith('--batch='):
                args.pop(0)
                batch_size = int(arg[8:])

            elif arg.startswith('--max='):
                args.pop(0)
                max_size = int(arg[6:])

            elif arg.startswith('--start='):
                args.pop(0)
                start = (arg[8:], )

            elif arg == '--next':
                args.pop(0)
                if self.next_key:
                    start = self.next_key
                else:
                    print "no next"
                    return

            elif arg in ['--array', '-a']:
                args.pop(0)
                as_array = True

            elif arg in ['--count', '-c']:
                args.pop(0)
                count = True

            elif arg[0] == '-' and arg[1:].isdigit():
                args.pop(0)
                max_size = int(arg[1:])

            elif arg == '--':
                args.pop(0)
                break

            elif arg.startswith('-'):
                args.pop(0)
                print "invalid argument: %s" % arg
                break

            else:
                break

        attr_keys = args[0].split(",") if args else None
        attrs = list(set(attr_keys)) if attr_keys else None

        #print "scan filter:%s attributes:%s limit:%s max:%s count:%s" % (scan_filter, attrs, batch_size, max, count)

        result = table.scan(scan_filter=scan_filter, attributes_to_get=attrs, request_limit=batch_size, max_results=max_size, count=count, exclusive_start_key=start)

        if count:
            print "count: %s/%s" % (result.scanned_count, result.count)
            self.next_key = None
        else:
            if as_array and attr_keys:
                self.print_iterator_array(result, attr_keys)
            else:
                self.print_iterator(result)

            self.next_key = result.last_evaluated_key

        if self.consumed:
            print "consumed units:", result.consumed_units

    def do_query(self, line):
        """
        query [:tablename] [-r] [--count|-c] [--array|-a] [-{max}] [{rkey-condition}] hkey [attributes,...]

        where rkey-condition:
            --eq={key} (equal key)
            --ne={key} (not equal key)
            --le={key} (less or equal than key)
            --lt={key} (less than key)
            --ge={key} (greater or equal than key)
            --gt={key} (greater than key)
            --exists   (key exists)
            --nexists  (key does not exists)
            --contains={key} (contains key)
            --ncontains={key} (does not contains key)
            --begin={startkey} (rkey begins with startkey)
            --between={firstkey},{lastkey} (between firstkey and lastkey)
        """

        table, line = self.get_table_params(line)
        args = self.getargs(line)

        condition = None
        count = False
        as_array = False
        max_size = None
        batch_size = None
        start = None

        if '-r' in args:
            asc = False
            args.remove('-r')
        else:
            asc = True

        while args:
            arg = args[0]

            if arg[0] == '-' and arg[1:].isdigit():
                max_size = int(arg[1:])
                args.pop(0)

            elif args[0].startswith('--max='):
                arg = args.pop(0)
                max_size = int(arg[6:])

            elif arg in ['--count', '-c']:
                count = True
                args.pop(0)

            elif arg in ['--array', '-a']:
                as_array = True
                args.pop(0)

            elif args[0].startswith('--batch='):
                arg = args.pop(0)
                batch_size = int(arg[8:])

            elif args[0].startswith('--start='):
                arg = args.pop(0)
                start = (arg[8:], )

            elif args[0] == '--next':
                arg = args.pop(0)
                if self.next_key:
                    start = self.next_key
                else:
                    print "no next"
                    return

            elif arg.startswith("--begin="):
                condition = BEGINS_WITH(self.get_typed_key_value(table, arg[8:], False))
                args.pop(0)
            elif arg.startswith("--eq="):
                condition = EQ(self.get_typed_key_value(table, arg[5:], False))
                args.pop(0)
            elif arg.startswith("--ne="):
                condition = NE(self.get_typed_key_value(table, arg[5:], False))
                args.pop(0)
            elif arg.startswith("--le="):
                condition = LE(self.get_typed_key_value(table, arg[5:], False))
                args.pop(0)
            elif arg.startswith("--lt="):
                condition = LT(self.get_typed_key_value(table, arg[5:], False))
                args.pop(0)
            elif arg.startswith("--ge="):
                condition = GE(self.get_typed_key_value(table, arg[5:], False))
                args.pop(0)
            elif arg.startswith("--gt="):
                condition = GT(self.get_typed_key_value(table, arg[5:], False))
                args.pop(0)
            elif arg == "--exists":
                condition = NOT_NULL()
                args.pop(0)
            elif arg == "--nexists":
                condition = NULL()
                args.pop(0)
            elif arg.startswith("--contains="):
                condition = CONTAINS(self.get_typed_key_value(table, arg[11:], False))
                args.pop(0)
            elif arg.startswith("--between="):
                parts = arg[10:].split(",", 1)
                condition = BETWEEN(self.get_typed_key_value(table, parts[0], True), self.get_typed_key_value(table, parts[1], False))
                args.pop(0)

            else:
                break

        hkey = self.get_typed_key_value(table, args.pop(0))
        attr_keys = args[0].split(",") if args else None
        attrs = list(set(attr_keys)) if attr_keys else None

        result = table.query(hkey, range_key_condition=condition, attributes_to_get=attrs, scan_index_forward=asc, request_limit=batch_size, max_results=max_size, count=count, exclusive_start_key=start)

        if count:
            print "count: %s/%s" % (result.scanned_count, result.count)
            self.next_key = None
        else:
            if as_array and attr_keys:
                self.print_iterator_array(result, attr_keys)
            else:
                self.print_iterator(result)

            self.next_key = result.last_evaluated_key

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

                for item in table.scan(attributes_to_get=[], request_limit=10):
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

        if self.conn:
            try:
                self.do_tables('')
            except:
                traceback.print_exc()

    def postloop(self):
        if self.history_file:
            readline.set_history_length(100)
            readline.write_history_file(self.history_file)

        print "Goodbye!"


def set_environment(env):
    found = False
    for section in ['Credentials', 'DynamoDB']:
        env_section = "%s.%s" % (env, section)

        if boto.config.has_section(env_section):
            found = True
            if not boto.config.has_section(section):
                boto.config.add_section(section)
            for o in boto.config.options(env_section):
                boto.config.set(section, o, boto.config.get(env_section, o))
    return found


def run_command():
    import sys

    args = sys.argv
    args.pop(0)  # drop progname

    verbose = False

    while args and args[0].startswith("-"):
        arg = args.pop(0)
        if arg.startswith("--env="):
            set_environment(arg[6:])
        elif arg.startswith("--verbose"):
            verbose = True
        elif arg == "--":
            break
        else:
            print "invalid option or parameter: %s" % arg
            sys.exit(1)

    DynamoDBShell(verbose).cmdloop()


if __name__ == '__main__':
    run_command()
