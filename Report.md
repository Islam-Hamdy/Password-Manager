# Design and Implementation #

## Master password manager ##
+ This class is mainly responsible for creating the user account using a new master password or login the system using a previous master password.
+ This class depends on a KeyGen object and uses SaltKeyPair instances.

+ The mechanism used to verify the supplied password for login is that this password is used to generate new keys using previously generated salts(stored in file) , these newly generated keys are compared to the old keys(stored in the same file along with the salts), if they are found to be identical then this is the correct master password.

##### KeyGen ######
+ This class derives the keys used in the next steps (encryptions and authentication) , it uses PBKDF2 to derive keys with length 128 bit , the salt supplied is a random number of 64 bit length.

+ The output of each generateKey() is a SaltKeyPair instance.

##### SaltKeyPair #####
+ This class contains methods needed to convert the derived key and its deriving salt to or from String representation.


## SavedPasswordManager ##

support adding, retrieving editing, removing and < domain-name, password > pairs.


```java
public SavedPasswordManager(byte[] encryptKey, byte[] MACKey)
```
>Creates a new savedPasswordManager. Accepts 2 keys (already computed from the master password) one for password encryption and the other for MACin procedures.

- - -

```java
public void add(String domain, String password) 
```
>1. Compute a tag (MAC) from the domain name using HMAC algorithm based on MAC-Key.
2. Salt the password, and save the < domain tag, Salt > to be used for verification.
3. Pad the salted password manually.
4. Apply  Galios Counter Mode GCM on the padded manually.
5. Save the < domain tag, encrypted password> pair to be used later for verification.
6. Save 64 byte token < domain tag || first 32 byte of the encrypted password > to be used against swapping attacks.

- - -

```java
public String get(String domain)
```
>Return the plain text password associated with the domain name, null if swapping attack was discovered.

- - -

```java
public void set(String domain, String newPassword)
```
>Replace the password associated with the domain name with the new password performing the same encryptions steps like ``add``.
- - -


```java
public void remove(String domain, String password)
```
>Removes the  < domain-name, password > pair from the system  after verifying that the password is correct.

- - -

##### Verify (Domain Name, Password) pair#####
1. compute the tag (MAC) for the domain name.
2. Compute the encryption of the passed password using the saved ``IV`` and ``Salt`` associated with the Domain Tag.
3. Check the computed password encryption against the saved encryption.
4. If the computed encryption is correct check against swap attacks (described later).

##### Stopping Swap Attacks #####
We save a 64 byte token; first 32 are the domain name tag (MAC), and the second 32 byte are the first 32 bytes from the encrypted password. On checking we recompute the token and check the computed token against the saved token.


##### Private Members #####
please see code comments for more details.
```java
private byte[] makeSwapBlockPair(byte[] domainTag, byte[] encryptedPass)
private boolean verify(String domain, String password)
private byte[] MACDomain(String domain)
private byte[] saltAndPad(String domainTag, String pass, byte[] salt)
private byte[] removePadAndSalt(byte[] paddedPass)
private byte[] encryptPassword(byte[] paddedPassword, byte[] IV)
private byte[] encryptPassword(byte[] paddedPassword)
private byte[] decryptPassword(byte[] passwordTag)
```
