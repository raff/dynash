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

import boto.dynamodb2
import boto.dynamodb2.layer1
import boto.dynamodb2.table
from boto.dynamodb2.exceptions import DynamoDBError
from boto.exception import BotoClientError, JSONResponseError
from boto.regioninfo import RegionInfo

import ast
import csv
import decimal
import json
import logging
import os
import os.path
import pprint
import re
import shlex
import sys
import time
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

        if isinstance(o, decimal.Decimal):
            return long(o) if o._isinteger() else float(o)

        return json.JSONEncoder.default(self, o)


class DynamoDBShell2(Cmd):

    prompt = "dynash2> "

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

        self.connect()

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
        self.next_key = None
        self.schema = {}
        self.verbose = verbose

        if verbose:
            self._onchange_verbose(None, verbose)

    def connect(self, accesskey=None, secret=None):
	region = boto.config.get('DynamoDB', 'region', None)
	host = boto.config.get('DynamoDB', 'host', None)
	port = boto.config.get('DynamoDB', 'port', None)
	is_secure = boto.config.getbool('DynamoDB', 'is_secure', True)

        params = {}

        if accesskey:
            params['aws_access_key_id'] = accesskey
            params['aws_secret_access_key'] = secret
        if region:
            params['region'] = region
        if host:
            params['host'] = host
        if port:
            params['port'] = host
        if is_secure:
            params['is_secure'] = is_secure

        self.conn = boto.dynamodb2.layer1.DynamoDBConnection(**params)

    def pprint(self, object, prefix=''):
        print "%s%s" % (prefix, self.pp.pformat(object) if self.pretty else str(object))

    def print_iterator(self, gen):
        encoder = DynamoEncoder()

        prev_item = None
        print "["

        for next_item in gen:
            if prev_item:
                print "  %s," % encoder.encode(prev_item)
            prev_item = dict(next_item.items())

        if prev_item:
            print "  %s" % encoder.encode(prev_item)

        print "]"


    def print_iterator_array(self, gen, keys):
        encoder = DynamoEncoder()
        writer = csv.writer(sys.stdout, quoting=csv.QUOTE_NONNUMERIC, doublequote=False, escapechar=str('\\'))

        def to_array(item):
            return [item.get(k) for k in keys]

        for item in gen:
            writer.writerow([(v or '').encode("utf-8") for v in to_array(item)])


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
            return boto.dynamodb2.table.Table(table_name.lstrip(':'), connection=self.conn), line
        else:
            return self.table, line

    def get_table(self, name):
        if name:
            return boto.dynamodb2.table.Table(name.lstrip(':'), connection=self.conn)
        else:
            return self.table

    def get_typed_key_value(self, table, value, is_hash=True):
        schema = table.schema
        keytype = None

        for s in schema:
            if is_hash and s.attr_type == 'HASH':
                keytype = s.data_type
                break
            if not is_hash and s.attr_type == 'RANGE':
                keytype = s.data_type
                break

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

    def get_key_name_value(self, table, value, is_hash=True):
        schema = table.schema
        keyname = None
        keytype = None

        for s in schema:
            keyname = s.name
            #print s.name, s.attr_type, s.data_type

            if is_hash and s.attr_type == 'HASH':
                keytype = s.data_type
                break
            if not is_hash and s.attr_type == 'RANGE':
                keytype = s.data_type
                break

        if not keytype:
            return {None: value}

        try:
            if keytype == 'S':
                return {keyname: str(value)}
            if keytype == 'N':
                return {keyname: float(value) if '.' in value else int(value)}
        except:
            pass

        return {keyname: value}

    def get_typed_value(self, field, value):
        field = field.split('__')[0]  # in dynamodb2 fields may contain a conditional as {name}__{conditional}

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
            self.connect(args[0], args[1])
        else:
            self.connect()

        self.do_tables('')

    def do_tables(self, line):
        "List tables"
        self.tables = self.conn.list_tables().get('TableNames')
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
                args = [ self.table.table_name ]
            else:
                args = self.tables

        for table in args:
            desc = self.conn.describe_table(table)

            if create_info:
                info = desc['Table']
                name = info['TableName']
                attributes = info['AttributeDefinitions']
                schema = info['KeySchema']

                hkey = ''
                rkey = ''

                for k in schema:
                    aname = k['AttributeName']
                    for a in attributes:
                        if a['AttributeName'] == aname:
                            value = "%s:%s" % (a['AttributeName'], a['AttributeType'])
                            break

                    if k['KeyType'] == 'HASH':
                        hkey = value
                    elif k['KeyType'] == 'RANGE':
                        rkey = ' ' + value

                prov = info['ProvisionedThroughput']
                prov = "-c %d,%d" % (prov['ReadCapacityUnits'], prov['WriteCapacityUnits'])
                print "create %s %s %s%s" % (name, prov, hkey, rkey)
            else:
                self.pprint(desc, "%s: " % table)

    def do_use(self, line):
        "use {tablename}"
        self.table = boto.dynamodb2.table.Table(line, connection=self.conn)
        self.pprint(self.table.describe())
        self.prompt = "%s> " % self.table.table_name

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

        schema = []

        hkey, _, hkey_type = args.pop(0).partition(':')
        hkey_type = self.get_type(hkey_type or 'S')
        schema.append(boto.dynamodb2.fields.HashKey(hkey, hkey_type))

        if args:
            rkey, _, rkey_type = args.pop(0).partition(':')
            rkey_type = self.get_type(rkey_type or 'S')
            schema.append(boto.dynamodb2.fields.RangeKey(rkey, rkey_type))

        t = boto.dynamodb2.table.Table.create(name,
                                              schema=schema,
                                              throughput={'read': rc, 'write': wc})
        self.pprint(t.describe())

    def do_drop(self, line):
        "drop {tablename}"
        self.get_table(line).delete()

    def do_refresh(self, line):
        "refresh {table_name}"
        table = self.get_table(line)

        while True:
            desc = table.describe()
            status = desc['Table']['TableStatus']
            if status == 'ACTIVE':
                break
            else:
                print status, "..."
                time.sleep(5)

        print ""
        self.pprint(desc)

    def do_capacity(self, line):
        "capacity [tablename] {read_units} {write_units}"
        table, line = self.get_table_params(line)
        args = self.getargs(line)

        read_units = int(args[0])
        write_units = int(args[1])

        desc = table.describe()
        prov = desc['Table']['ProvisionedThroughput']

        current_read, current_write = prov['ReadCapacityUnits'], prov['WriteCapacityUnits']
        if read_units < current_read or write_units < current_write:
            print "%s: updating capacity to %d read units, %d write units" % (table.table_name, read_units, write_units)
            print ""
            if not table.update(throughput={'read': read_units, 'write': write_units}):
                print "update failed"
            else:
                self.do_refresh(table.table_name)

        else:
            print "%s: current capacity is %d read units, %d write units" % (table.table_name, current_read, current_write)
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

                print "%s: updating capacity to %d read units, %d write units" % (table.table_name, current_read, current_write)
                if not table.update({'read': current_read, 'write': current_write}):
                    print ""
                    print "update failed"
                    print ""
                    break
                else:
                    print ""
                    self.do_refresh(table.table_name)
                    print ""

    def do_put(self, line):
        "put [:tablename] [!fieldname:expectedvalue] {json-body} [{json-body}, {json-body}...]"
        table, line = self.get_table_params(line)
        expected, line = self.get_expected(line)
        if expected:
            print "expected: not yet implemented"
            return

        if line.startswith('(') or line.startswith('['):
            print "batch: not yet implemented"
            return

            list = self.get_list(line)
            wlist = self.conn.new_batch_write_list()
            wlist.add_batch(table, [ table.new_item(None, None, item) for item in list ])
            response = self.conn.batch_write_item(wlist)
            consumed = response['Responses'][table.table_name]['ConsumedCapacityUnits']

            if 'UnprocessedItems' in response and response['UnprocessedItems']:
                print ""
                print "unprocessed: ", response['UnprocessedItems']
                print ""
        else:
            item = json.loads(line)
            table.put_item(item)
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
            table.put_item(item)
            #consumed += item.consumed_units
            items += 1
            print item['id']

        print "imported %s items, consumed units:%s" % (items, consumed)

    def _todo_do_update(self, line):
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
            print "batch: not yet implemented"
            return

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

            for item in response['Responses'][table.table_name]['Items']:
                ordered[(item.get(hkey), item.get(rkey))] = item

            self.pprint(filter(None, ordered.values()))
        else:
            args = self.getargs(line)

            key = self.get_key_name_value(table, args[0], True)
            print key

            if len(args) > 1:
                key.update(self.get_key_name_value(table, args[1], False))

            print key

            item = table.get_item(consistent=self.consistent, **key)
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
        scan [:tablename] [--batch=#] [-{max}] [+filter_attribute=filter_value] [attributes,...]

        filter_attribute is either the field name to filter on or a field name with a conditional, as specified in boto's documentation,
        in the form of {name}__{conditional} where conditional is:

            eq (equal value)
            ne {value} (not equal value)
            lte (less or equal then value)
            lt (less then value)
            gte (greater or equal then value)
            gt (greater then value)
            null (value is null / does not exists - pass true/false)
            contains (contains value)
            ncontains (does not contains value)
            beginswith (attribute begins with value)
            in (value in range)
            between (between value1 and value2 - use: between=value1,value2)
        """

        table, line = self.get_table_params(line)
        args = self.getargs(line)

        scan_filter = {}
        #count = False
        as_array = False
        max_size = None
        batch_size = None
        start = None
        cond = None

        while args:
            if args[0].startswith('+'):
                arg = args.pop(0)
                filter_name, filter_value = arg[1:].split('=', 1)

                if "__" not in filter_name:
                    filter_name += "__eq"

                if filter_name.endswith("__null"):
                    scan_filter[filter_name] = filter_value == "true"
                else:
                    scan_filter[filter_name] = self.get_typed_value(filter_name, filter_value)

            elif args[0].startswith('--batch='):
                arg = args.pop(0)
                batch_size = int(arg[8:])

            elif args[0].startswith('--max='):
                arg = args.pop(0)
                max_size = int(arg[6:])

            elif args[0].startswith('--start='):
                arg = args.pop(0)
                start = (arg[8:], )

            elif args[0] == "--and":
                args.pop(0)
                cond = "AND"

            elif args[0] == "--or":
                args.pop(0)
                cond = "OR"

            elif args[0] == '--next':
                arg = args.pop(0)
                if self.next_key:
                    start = self.next_key
                else:
                    print "no next"
                    return

            elif args[0] == '-a' or args[0] == '--array':
                as_array = True
                args.pop(0)

            elif args[0].startswith('-'):
                arg = args.pop(0)

                #if arg == '-c' or arg == '--count':
                #    count = True

                if arg[0] == '-' and arg[1:].isdigit():
                    max_size = int(arg[1:])

                elif arg == '--':
                    break

                else:
                    print "invalid argument: %s" % arg
                    break

            else:
                break

        attr_keys = args[0].split(",") if args else None
        attrs = list(set(attr_keys)) if attr_keys else None

        result = table.scan(limit=max_size, max_page_size=batch_size, attributes=attrs, conditional_operator=cond, exclusive_start_key=start, **scan_filter)

        #
        # enable this if you want to see when pages are fetched
        #
        if False:
            _fetch_more = result.fetch_more
            def fetch_more():
                print "==== fetch page ===="
                _fetch_more()

            result.fetch_more = fetch_more

        if False: # count:
            print "count: %s/%s" % (result.scanned_count, result.count)
            self.next_key = None
        else:
            if as_array and attr_keys:
                self.print_iterator_array(result, attr_keys)
            else:
                self.print_iterator(result)

            self.next_key = result._last_key_seen

        if self.consumed:
            print "consumed units:", result.consumed_units

    def do_query(self, line):
        """
        query [:tablename] [-r] [-{max}] [{rkey-condition}] hkey [attributes,...]

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

            elif arg == '-c' or arg == '--count':
                count = True
                args.pop(0)

            elif arg == '-a' or arg == '--array':
                as_array = True
                args.pop(0)

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

            elif args[0].startswith('--batch='):
                arg = args.pop(0)
                batch_size = int(arg[8:])

            elif args[0].startswith('--max='):
                arg = args.pop(0)
                max_size = int(arg[6:])

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
            else:
                break

        hkey = self.get_typed_key_value(table, args[0])
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

            #self.next_key = result.last_evaluated_key


        if self.consumed:
            print "consumed units:", result.consumed_units

    def do_rmall(self, line):
        "remove [tablename...] yes"
        args = self.getargs(line)
        if args and args[-1] == "yes":
            args.pop()

            if not args:
                args = [self.table.table_name]

            while args:
                table = boto.dynamodb2.table.Table(args.pop(0), connection=self.conn)
                print "from table " + table.table_name

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
        except JSONResponseError as e:
            print e.error_message
        except (DynamoDBError, BotoClientError) as e:
            print self.pp.pformat(e)
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
        print "\ndynash2 %s: A simple shell to interact with DynamoDB" % __version__

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

    DynamoDBShell2(verbose).cmdloop()


if __name__ == '__main__':
    run_command()
