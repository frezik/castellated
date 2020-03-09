import * as Castle from '../src/castellated';
import * as Auth from '../src/auth/bcrypt';
import * as Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 2 );
Auth.register( "10" );

const stored_passwd = new Password.PasswordString( [
    "ca571e"
    ,"v1"
    ,"bcrypt"
    ,"10"
    // bcrypt string of "foobar"
    ,"$2b$10$wOWIkiks.tbbftwkJ81BNeuOtq631SzbsVOO7VAHf5ziH.edAAqJi"
].join("-") );
const crypt = new Auth.BcryptAuth( "10" );

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
