import * as Castle from '../src/castellated';
import Auth from '../src/auth/scrypt';
import Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 5 );
Auth.register();

const SCRYPT_ARGS_STRING = 'c:16384,b:8,p:1,s:16,k:64,e:h,l:5476558450e3f2d9818d81b61ed570e1';
const stored_passwd = new Password( [
    "ca571e"
    ,"v1"
    ,"scrypt"
    ,SCRYPT_ARGS_STRING
    // scrypt string of "foobar"
    ,"cbeabcfbbdb72f771ea2315d4deb40097ba7c95709a907edb3b811293160273e87f997bd02830e670e7d22c79136681c75035117553d50a04859bb43c7b6da41"
].join("-") );
const crypt = new Auth( SCRYPT_ARGS_STRING );

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

crypt
    .encode( "foobar" )
    .then( (result) => {
        return crypt.isMatch(
            "foobar"
            ,stored_passwd
        );
    })
    .then( (result) => {
        Tap.ok( result, "Encoded password correctly" );
    });

const same_auth = new Password( [
    "ca571e"
    ,"v1"
    ,"scrypt"
    ,SCRYPT_ARGS_STRING
    ,"barfoo"
].join("-") );
const diff_auth = new Password( [
    "ca571e"
    ,"v1"
    ,"scrypt"
    ,'c:16384,b:16,p:1,s:16,k:64,e:h,l:5476558450e3f2d9818d81b61ed570e1'
    ,"foobar"
].join("-") );
Tap.ok( crypt.sameAuth( same_auth ), "Same auth checked correctly" );
Tap.ok(! crypt.sameAuth( diff_auth ), "Different auth checked correctly" );
