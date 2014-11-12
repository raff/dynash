dynash
======
A simple "shell" to access DynamoDB via "boto".

### Usage
    # boto dynamodb APIs
    > dynash [--verbose] [--env=environment]

    # boto dynamodb2 APIs
    > dynash2 [--verbose] [--local] [--env=environment]
    
### Description
You can create/delete/list/describe tables, add/modify/delete/list records and more.

- ls: list tables

- create {tablename}: create table

- delete {tablename}: delete table

- describe {tablename}: describe table

- capacity {tablename} {read_capacity} {write_capacity}: update table capacity

- use {tablename}: select table

- scan/l: list table content

- get {id}: get item(s) from table

- put {id} {properties}: add item to table

- update {id} {properties}: update item

- rm {id}: remove item from table

- query/q: query table 

and many more (use 'help' to find the available commands)

### Note:

- Credentials should be in your .boto config file under the [Credentials] (see http://docs.pythonboto.org/en/latest/boto_config_tut.html)

- You can specify the DynamoDB region to use and other DynamoDB related configuration entries in your .boto config under the [DynamoDB] section:

    [DynamoDB]
    region=us-west-1

- You can specify alternative environments in your .boto by adding boto sections prefixed with the environment name, and then selecting the environment at startup:

    --- .boto -------
    [Credentials]
      ...
    [env.Credentials]
      ...
    [env.DynamoDB]
      ...

    --- run --------
    > dynash --env=env

- Item related commands use the currently selected table (see 'use' command) but you can pass a table name as first parameter prefixed by ':'
 
- Command completion is enabled (and it will complete table names)

- You can set various flags (like debug, verbose, pretty-print, etc.) using the 'set' command (try 'set -l')k

- You can redirect the output of commands using standard shell redirection ( > outfile )

- You can execute shell commands using '!shell command'

