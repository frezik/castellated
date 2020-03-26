# Castellated

An adaptable, robust password storage system.

Good advice in storing passwords usually involves using specific algorithms, 
such as bcrypt. This is fine advice, but usually misses a key design factor: 
adaptability.

Advice on which password encoding to use has changed several times over the 
years. The oldest systems stored passwords in plaintext. Then Unix started 
storing things with `crypt()`. That was soon broken, so things switched to 
MD5, and then MD5 with salt. MD5 itself was weak, so salted SHA1 was used 
instead. GPU-based attacks then prompted a move to systems with 
configurable cost parameters, such as bcrypt and scrypt.

It's unlikely that we're at the end of the line.

With each step, old systems were often not updated. Thus, at the time of 
this writing in 2020, we still hear about password databases being stolen 
that are full of unsalted MD5 passwords, or sometimes even plaintext.

The standard advice is missing adaptability. Consider these situations:

* You run bcrypt. Tommorow morning, reports come out showing that bcrypt is 
  completely broken. How does your system respond?
* You run bcrypt, and have for several years. Have you tested recently to see 
  if your cost parameter is robust against the current state of hardware? If 
  you determine that it should be higher, how much code would you have to 
  change to get there? Would the strengthened parameter only apply to 
  new user signups, or would old users be updated automatically when they 
  next sign in?
* You run a password storage system that was coded by some guy who left the 
  company 5 years ago. It doesn't use salt, or it uses a weak salt, or it 
  uses `crypt()`, or it has any number of other problems that make it weaker 
  than it should be. You would like to replace it, but what do you do with 
  all the passwords already in the system?

Standard password storage advice rarely touches on these issues.

Castellated is a framework designed to make it easy to migrate password 
storage systems. Out of the box, it supports storing in argon2, bcrypt, and 
scrypt. Plugins may provide other means.

Castellated stores not just the password, but a configuration string that 
specifies how the password was encoded. You then configure a prefered method, 
including any special parameters your encoding method uses. All new users are 
automatically set to the preferred method. If an old user logs in (which means 
we have access to the plaintext password), and they're still on an old method, 
then they're automatically upgraded to the new preferred method.

Unfortuately, we can't do anything for existing users until we have the 
plaintext password in some form. Assuming we did our job right, that is. This 
framework is about doing our job right, so we have to live with this limitation.
If possible, encourage your users to login on a regular basis, especially after 
a new password storage config is pushed to production.

Since you may need to migrate an exsiting password storage system, there is 
also provision to help that process.

## Hashing vs Encrypting vs Encoding

Common advice is to hash passwords rather than using encryption algorithms. 
An encryption algorithm would mean there's a single key somewhere that's 
encrypting the key, which has to be stored. Someone has to have access to 
that place. With hashes, things are one-way. Even the implementers and system 
administrators would not be able to break the passwords (if they did their job 
right, of course).

This is very good advice, but gives us a bit of a terminalogy problem here. 
Castellated is meant to be a generic method of handling passwords, without a 
care of using a hash or an encryption algorithm. Not only that, but some key 
derivation functions (specifically, bcrypt) use a block cipher at their core, 
which blurs the distinction between hasing and encryption.

Throughout the documentation for Castellated, we try to use the term "encoded" 
as a generic way of talking about protecting passwords. This does conflict 
somewhat with encoding methods that aren't meant for security (like hex or 
base64), but seems the best optional overall. We recommend setting pedantry 
aside and using "hash", "encrypt", and "encode" interchangably in this context.

## The Storage String

The passwords are stored as a string, which has fields separted by '-'. Here's 
an example of a bcrypt string:

    ca571e-v1-bcrypt-10-$2b$10$wOWIkiks.tbbftwkJ81BNeuOtq631SzbsVOO7VAHf5ziH.edAAqJi

The fields are:

* "ca571e" - A magic string indicating this is a Castellated string
* "v1" - Version 1 of the string
* "bcrypt" - A short name identifying this as a bcrypt encoded password
* "10" - The parameter field. In this case, it signifies that this bcrypt string was encoded with a difficulty of 10
* "..." - The encoded password

The internal format of the parameter field is determined by the authenticator 
implementing it. Since bcrypt only has a single cost field, it puts that lone 
number as its parameter field. An scrypt string has a more complicated 
format. Each authenticator should cover their parameter string in their own 
documentation.


## Storage Requirements

Just about any database will do, provided the password field can take a string 
of arbitrary length. Castellated strings can get relatively long; a hex-encoded 
scrypt string in our test suite, for example, is 210 characters. We don't 
expect even that's an upper limit on length.

Be sure your password field can take a very long string, perhaps as much 
as 1024 characters. If possible, leave it unbounded.

*The string can contain newlines*. Be sure your storage mechanism allows this. 
You may want to test storing the [Big List of Naughty Strings](https://github.com/minimaxir/big-list-of-naughty-strings)
using the plaintext authenticator. That should iron out issues like this.


## Basic Usage

We start by importing Castellated and then registering any authenticators you 
need.

  import Castle from 'castellated';
  import CustomAuth from 'MyCustomAuth';
  
  CustomAuth.register();

By default, the system is already registered with authenticators for 
argon2, bcrypt, plaintext, and scrypt. Note that the plaintext authenticator 
is not recommended, and mostly exists for testing purposes.

Next, we instantiate the main object, passing in our preferred encoding type 
and a parameter string for it. We also pass in some callbacks, which we will 
cover below.

    const castle = new Castle(
        "bcrypt"
        ,"10"
        ,fetch_callback
        ,update_callback
        ,add_user_callback
    );

In this case, we want all new passwords to be stored with bcrypt, with a cost 
of 10. Passwords in the database can be encoded by any means that was registered 
above, but when we get new logins with valid credentials, they will be encoded 
to this preferred type.

The callbacks are how you'll hook into your database to fetch, update, and add 
users. Here's the list:

### fetch_callback

    (
        username: string
    ): Promise<string>

Takes the username, and returns a promise that will return the password for 
the given user.

### update_callback

    (
        username: string
        ,passwd: string
    ): Promise<void>

Returns a promise that will update the password for the given user.

### add_user_callback

    (
        username: string
        ,passwd: string
    ): Promise<void>

Returns a promise that will add a new user with the given username and password.

## Matching Passwords

Call `match()` with the username and password. It returns a promise that will 
give you a boolean of whether or not the password matched. This uses 
`fetch_callback` to get the password from your database.

Example:

    castle
        .match( "user@example.com", "verysecurepassword" )
        .then( (is_matched) => {
            console.log( "Matched: " + is_matched );
        });

If the password matched, but it wasn't stored in the preferred method, this 
will automatically encode it to the new method and call `update_callback` 
to store it.

If it doesn't recognize the stored string as being a Castellated format, it will 
check with the fallback authenticator. See "Migrating to Castellated" below.

## Adding a User

The `addUser()` method will take a username and plaintext password, encode it 
by the preferred type, and add it to your database with `add_user_callback`. 
Returns a promise (which itself returns void).

Example: 

    castle
        .addUser( "user@example.com", "verysecurepassword" )
        .then( () => {
            console.log( "Password stored" );
        });

## Migrating to Castellated

You likely have a passwords stored by some mechanisim already, and would like 
to migrate to Castellated. Since the strings you currently store wouldn't be 
compatible, we provide a fallback authentication method. Set it with 
`setFallbackAuthenticator()`.

Here's an example where `old_password` is stored in a constant in plaintext.

    const old_password = "verysecurepassword";
    
    castle.setFallbackAuthenticator(
        (
            username: string
            ,passwd: string
        ): Promise<boolean> => {
            return new Promise( (result, reject) => {
                const is_matched = castle.isMatch( old_password, passwd );
                result( is_matched );
            });
        }
    );

The fallback authenticator is a callback that takes a username and password, 
and returns a promise that returns a boolean. That boolean indicates if the 
given user/pass pair was valid.

When calling `match()`, this will get called for any strings that don't match 
the usual Castellated format. If it's good to go, expect `update_callback` to 
get hit for storing a new string in Castellated format.

The code above uses `isMatch()` to check if the two strings are equal. This 
runs a constant-time algorithm, which prevents timing attacks. It's highly 
recommended to use this for password matching rather than 
`old_password == passwd` or something similar.

## Writing a New Authentication Method

If you want to write a new method of encoding passwords, start by implementing 
the Authenticator interface. This has three methods, documented below. You also 
need some way to register your new class with the overall system; by convention, 
this is done with a `register()` static method. Finally, you'll be working 
with the `PasswordString` object a lot, so be sure to read its documentation.

### isMatch

    isMatch(
        incoming_passwd: string
        ,stored_passwd: PasswordString
    ): Promise<boolean>

Returns a promise that returns true if the incoming plaintext password matches 
the stored password (which will be encoded and in a `PasswordString` object).

If the underlying library does not have a way to match passwords on its own
, then you'll be tempted to write code like this:

    const encoded_incoming_passwd = encode( incoming_passwd );
    return ( encoded_incoming_passwd == stored_passwd.passwd_data );

This code is vulnerable to timing attacks, as languages optimize their string 
comparison to return false as soon as the first character doesn't match.
Instead, use `isMatch()` from the main Castellated module:

    import Castle from 'castellated';
    ...
    const encoded_incoming_passwd = encode( incoming_passwd );
    return Castle.isMatch( encoded_incoming_passwd, stored_passwd.passwd_data );

I know, you probably don't think it's possible for an attacker to figure out 
the password by looking at small timing differences. In fact, timing attacks 
on password matching has been done before in the wild. We made it easy to 
do it right, so why not do it?

### sameAuth

    sameAuth(
        passwd: PasswordString
    ): boolean

Return true if the `PasswordString` object is the same kind of authenticator 
as you. This includes not just the name of the authenticator (like bcrypt), but 
also that all important parameters match.

### encode

    encode(
        passwd: string
    ): Promise<PasswordString>

Gets a plaintext password. Returns a promise that returns the encoded password 
as a `PasswordString` object.

### static register()

By convention, we have a static method named `register()` that registers the 
authenticator with Castellated. This is done by calling
`Castellated.registerAuthenticator()`.

That method takes the name of your authenticator (like bcrypt) and a callback.
The callback takes a string, which would be the argument string that your 
authenticator encodes into `PasswordString.crypt_args`. It should return 
an instantiated object of your authenticator.

Example:

        Castellated.registerAuthenticator( "bcrypt", 
            ( args_str: string): Authenticator => {
                return new BcryptAuth( args_str );
            }
        );

Since this is convention, you're free to register by some other mechanisim. 
You only need to call `Castellated.registerAuthenticator()` by some means.

## Copyright

Copyright (c) 2020,  Timm Murray
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, 
      this list of conditions and the following disclaimer in the documentation 
      and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
