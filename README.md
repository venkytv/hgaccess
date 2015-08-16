# hgaccess
Script to restrict access to Mercurial repos shared over SSH.

Setup
=====

1. Copy the script somewhere in the box hosting the Mercurial repositories.  The
   only requirement is that the user whose account is being used to share the
   repositories has access to execute this script.
2. Create a `hgaccess.conf` file in the SSH user's home directory containing the
   mapping of user roles to repositories.  Use the included
   [hgaccess.conf.SAMPLE](hgaccess.conf.SAMPLE) file as a sample.  The repo
   names listed in the file (in the "read" and "write" entries) are the paths
   relative to the home directory of the repo serving SSH user.  For instance,
   if the repo is in the home directory and has a name "foo", the entries in
   `hgaccess.conf` referring to the repo will just use the name "foo".  If the
   repo is in a directory `~/repos/foo`, the repo name in `hgaccess.conf` will
   be "repos/foo".
3. Create a `hgadmin.list` file in the same directory containing the list of
   users who are allowed access to the admin interface.  Use the included
   [hgadmin.list.SAMPLE](hgadmin.list.SAMPLE) file as an example.

Adding Users
============

The first user seems to be set up by hand.  Add an entry similar to the
following to the SSH user's `.ssh/authorized_keys` file:

    command="/home/hg/bin/hgaccess.pl admin:eng",no-port-forwarding,no-x11-forwarding,no-agent-forwarding ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABA3XOS9JwRu+r5hVjn9aFSCriU0bsji5HKYr1Oy2CILOqSdn3B4tD9WhfvYHoyAesZ7/qRM29jhU90assZWund1+OunZ7jwFXznNRt2BscnIWyx9u3Zl36ePh1njufNwssTxTnZ1kGLXKImHu78mmOb5C6XYLEhaQoP1B1z0M7ElR+OfHZVlWAuI9L+YUcq6y2V4WSoGFmN6dmNRmCsPNFC90ognZf/xMDMg9cmH5gNLsieSCDXYt+6Z admin@example.com

This example assumes the script is installed at `/home/hg/bin/hgaccess.pl`, the
username is `admin`, and the role the user belongs to is `eng`.

Optionally (but recommended), also add this user to the `hgadmin.list` list.
This will allow the user to use the admin interface.

Admin Interface
===============

Any valid user whose username is listed in the `hgadmin.list` file is allowed
access to the admin interface.  To access the admin interface, just ssh to the
account hosting the repositories.  For example:

    ssh hg@reposvr help

Admin Commands
==============

    ADMIN COMMANDS:
    ==============
    
    - gates
      List available gates (repos).
    
    - users
      List known users.
    
    - adduser <user> <role>[,<role>...] <public-key>
      Add a user to the access list (authorized_keys).
    
    - validate
      Validate config (authorized_keys).
    
    - status <gate>
      Report status of specified gate.
    
    - lock <gate>
      Lock specified gate.
    
    - unlock <gate>
      Unlock specified gate.
    
    - open <gate> <user> [<user>...]
      Allow listed user(s) push access to locked gate.
    
    - close <gate> <user> [<user>...]
      Revoke push access to locked gate for listed user(s).
    
    - help
      Display this message.
    
    NOTE: If no command is specified, the admin user is dropped into a shell.

