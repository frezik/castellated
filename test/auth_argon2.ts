import * as Castle from '../src/castellated';
import * as Auth from '../src/auth/argon2';
import * as Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 2 );
Auth.register();

const ARGON2_ARGS_STRING = 't:3,m:65536,p:2,f:2i';
const stored_passwd = new Password.PasswordString( [
    "ca571e"
    ,"v1"
    ,"argon2"
    ,ARGON2_ARGS_STRING
    // argon2 string of "foobar"
    ,"$argon2i$v=19$m=65536,t=3,p=2$4ov06yahY3n+ihIMvdShiA$d8jp/Ozv++K2J6exyPruFT0Xvz4blC58EwGV628+5oY"
].join("-") );
const crypt = new Auth.Argon2Auth( ARGON2_ARGS_STRING );

Tap.comment( `Stored password: ${stored_passwd}` );
Tap.comment( `Stored password parsed: ${stored_passwd.passwd_data}` );

crypt.isMatch(
    "foobar"
    ,stored_passwd
).then( (result) => {
    Tap.ok( result, "Password matches" );
});
crypt.isMatch(
    "barfoo"
    ,stored_passwd
).then( (result) => {
    Tap.ok(! result, "Bad password doesn't match" );
});


// TODO encode password, same auth check