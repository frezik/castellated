import * as Castle from '../src/castellated';
import * as Auth from '../src/auth/scrypt';
import * as Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 2 );
Auth.register();

const SCRYPT_ARGS_STRING = 'c:16384,b:8,p:1,s:16,k:64,e:h,l:5476558450e3f2d9818d81b61ed570e1';
const stored_passwd = new Password.PasswordString( [
    "ca571e"
    ,"v1"
    ,"scrypt"
    ,SCRYPT_ARGS_STRING
    // scrypt string of "foobar"
    ,"cbeabcfbbdb72f771ea2315d4deb40097ba7c95709a907edb3b811293160273e87f997bd02830e670e7d22c79136681c75035117553d50a04859bb43c7b6da41"
].join("-") );
const crypt = new Auth.ScryptAuth( SCRYPT_ARGS_STRING );

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
