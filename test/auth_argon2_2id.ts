import * as Castle from '../src/castellated';
import Auth from '../src/auth/argon2';
import Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 2 );
Auth.register();

const ARGON2_ARGS_STRING = 't:3,m:65536,p:2,f:2d';
const stored_passwd = new Password( [
    "ca571e"
    ,"v1"
    ,"argon2"
    ,ARGON2_ARGS_STRING
    // argon2 string of "foobar"
    ,"$argon2id$v=19$m=65536,t=3,p=2$d2UHWFZ/MxtJK7DidBVEgQ$C8G5N6oroGLKv4sF0LLdHh7e8KD8jACbt7JFzTEf6wA"
].join("-") );
const crypt = new Auth( ARGON2_ARGS_STRING );

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
