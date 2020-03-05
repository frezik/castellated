import * as Castle from '../src/castellated';
import * as Auth from '../src/auth/plaintext';
import * as Tap from 'tap';

const stored_passwd = new Castle.PasswordString( [
    "ca571e"
    ,"v1"
    ,"plain"
    ,"plain"
    ,"foobar"
].join("-") );
const plain = new Auth.PlaintextAuth();

Tap.comment( `Stored password: ${stored_passwd}` );
Tap.comment( `Stored password parsed: ${stored_passwd.passwd_data}` );

Tap.ok( plain.isMatch(
    "foobar"
    ,stored_passwd
), "Password matches" );
Tap.ok(! plain.isMatch(
    "barfoo"
    ,stored_passwd
), "Bad password doesn't match" );
