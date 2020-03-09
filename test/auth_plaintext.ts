import * as Castle from '../src/castellated';
import * as Auth from '../src/auth/plaintext';
import * as Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 2 );
Auth.register("");

const stored_passwd = new Password.PasswordString( [
    "ca571e"
    ,"v1"
    ,"plain"
    ,"plain"
    ,"foobar"
].join("-") );
const plain = new Auth.PlaintextAuth();

Tap.comment( `Stored password: ${stored_passwd}` );
Tap.comment( `Stored password parsed: ${stored_passwd.passwd_data}` );

plain.isMatch(
    "foobar"
    ,stored_passwd
).then( (result) => {
    Tap.ok( result, "Password matches" );
});
plain.isMatch(
    "barfoo"
    ,stored_passwd
).then( (result) => {
    Tap.ok(! result, "Bad password doesn't match" );
});
