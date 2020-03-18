import * as Castle from '../src/castellated';
import Auth from '../src/auth/bcrypt';
import * as Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 5 );
Auth.register();

const stored_passwd = new Password.PasswordString( [
    "ca571e"
    ,"v1"
    ,"bcrypt"
    ,"10"
    // bcrypt string of "foobar"
    ,"$2b$10$wOWIkiks.tbbftwkJ81BNeuOtq631SzbsVOO7VAHf5ziH.edAAqJi"
].join("-") );
const crypt = new Auth( "10" );

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

const same_auth = new Password.PasswordString( [
    "ca571e"
    ,"v1"
    ,"bcrypt"
    ,"10"
    ,"foobar"
].join("-") );
const diff_auth = new Password.PasswordString( [
    "ca571e"
    ,"v1"
    ,"bcrypt"
    ,"11"
    ,"foobar"
].join("-") );
Tap.ok( crypt.sameAuth( same_auth ), "Same auth checked correctly" );
Tap.ok(! crypt.sameAuth( diff_auth ), "Different auth checked correctly" );
