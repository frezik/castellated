import * as Castle from '../src/castellated';
import Auth from '../src/auth/plaintext';
import BcryptAuth from '../src/auth/bcrypt';
import Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 5 );
Auth.register();
BcryptAuth.register();

const stored_passwd = new Password( [
    "ca571e"
    ,"v1"
    ,"plain"
    ,"plain"
    ,"foobar"
].join("-") );
const plain = new Auth();

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

plain.encode( "foobar" ).then( (result) => {
    Tap.equal( result.toString(), stored_passwd.toString(),
        "Encoded password correctly" );
});

const same_auth = new Password( [
    "ca571e"
    ,"v1"
    ,"plain"
    ,"plain"
    ,"barfoo"
].join("-") );
const diff_auth = new Password( [
    "ca571e"
    ,"v1"
    ,"bcrypt"
    ,"plain"
    ,"barfoo"
].join("-") );
Tap.ok( plain.sameAuth( same_auth ), "Same auth checked correctly" );
Tap.ok(! plain.sameAuth( diff_auth ), "Different auth checked correctly" );
