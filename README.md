Password-Manager
================

[Cryptography course project] # User Manual guide :

### Project Description :

In this project you will implement a password manager. The password manager
stores the passwords for every domain the user wishes to. The password manager
should satisfy the following requirements.

```
1. A master passwords should be used to generate the encryption and authenti-
cation keys needed using PBKDF2.

2. Password manager should not store any information about its master pass-
word, it is supplied by its user. The Password manager should detect when a
wrong password is supplied.

3. Password manager should support the addition, modification and deletion of
a password for any given domain.

4. Password manager should store the passwords padded to a length of 32 bytes,
so that no information is revealed about the length of password for a given
domain, assuming that the maximum password length is 32 bytes. (32 Can
be replaced by any number of your choice)

5. Passwords should be stored encrypted and authenticated using Galois Counter
Mode (GCM).

6. Domain names are not stored. A MAC using HMAC is stored in the table
instead. Subsequent lookups will be using this HMAC derived using HMAC
on the domain name.

7. The Password manager should be able to prevent swap attacks, that is, an
attacker swapping the passwords of two domains. For example if the attacker
swaps the passwords for the domain www.yahoo.com with the password for
the domain www.facebook.com, the password manger should be able to detect
that an error has happened.
```

### Requirements :

 * JDK 1.5 - JDK 1.7 (Bouncy Castle latest version).

###  Guide :


```
1. Enter your master password : 
	abc.abc.abc

2. if ( valid password ) 
		"Successful login, valid password !"
   else
   		"New account created !"

3. Enter a series of the mentioned supported functions.

4. Press CTRL+D (EOF) to close the input stream.

5. Re-run the program and use your master password for verification.

```


###  Supported functions :

Stick to the following format!

```
add <domain_name> <password>
```

```
set <domain_name> <new_password>
```

```
remove <domain_name> <password>
```

```
get <domain_name>
```

 
This is [on GitHub](https://github.com/jbt/markdown-editor) so let me know if I've b0rked it somewhere.


Props to Mr. Doob and his [code editor](http://mrdoob.com/projects/code-editor/), from which
the inspiration to this, and some handy implementation hints, came.

### Stuff used to make this:

 * [marked](https://github.com/chjj) for Markdown parsing
 * [CodeMirror](http://codemirror.net/) for the awesome syntax-highlighted editor
 * [highlight.js](http://softwaremaniacs.org/soft/highlight/en/) for syntax highlighting in output code blocks
 * [js-deflate](https://github.com/dankogai/js-deflate) for gzipping of data to make it fit in URLs
