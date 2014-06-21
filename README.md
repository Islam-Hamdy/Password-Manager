# Password-Manager [Cryptography course project]

-------------------
### Project Description :

In this project you will implement a password manager. The password manager
stores the passwords for every domain the user wishes to. The password manager
should satisfy the following requirements.


1. A master passwords should be used to generate the encryption and authenti-
cation keys needed using PBKDF2.

* Password manager should not store any information about its master pass-
word, it is supplied by its user. The Password manager should detect when a
wrong password is supplied.

* Password manager should support the addition, modification and deletion of
a password for any given domain.

* Password manager should store the passwords padded to a length of 32 bytes,
so that no information is revealed about the length of password for a given
domain, assuming that the maximum password length is 32 bytes. (32 Can
be replaced by any number of your choice)

* Passwords should be stored encrypted and authenticated using Galois Counter
Mode (GCM).

* Domain names are not stored. A MAC using HMAC is stored in the table
instead. Subsequent lookups will be using this HMAC derived using HMAC
on the domain name.

* The Password manager should be able to prevent swap attacks, that is, an
attacker swapping the passwords of two domains. For example if the attacker
swaps the passwords for the domain www.yahoo.com with the password for
the domain www.facebook.com, the password manger should be able to detect
that an error has happened.

-------------------
### System Requirements :

 * JDK 1.5 - JDK 1.7 (Bouncy Castle latest version).

-------------------
### User Guide : 

11. Enter your master password : 
	abc.abc.abc

* if ( valid password ) 
	* Successful login, valid password !
  
  else
   * New account created !

* Enter a series of the mentioned supported functions.

* Press CTRL+D (EOF) to close the input stream.

* Re-run the program and use your master password for verification.

-------------------

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

-------------------
 
###  Project report :

Report can be found in this [link](https://github.com/jbt/markdown-editor).

-------------------

### Useful stuff used to make this:

 * [Markdown cheatsheet](https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet) for Markdown parsing.
 * [BouncyCastle](http://www.bouncycastle.org/latest_releases.html) for latest releases.
