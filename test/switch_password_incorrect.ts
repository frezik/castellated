import * as Castle from '../index';
import * as BcryptAuth from '../src/auth/bcrypt';
import * as PlainAuth from '../src/auth/plaintext';
import * as Tap from 'tap';

const USERNAME = "foo";
const GOOD_PASSWD = "ca571e-v1-plain-plain-secretpass";
const GOOD_PASSWD_UNENCODED = "secretpass";
const BAD_PASSWD = "bar";

Tap.plan( 2 );
BcryptAuth.register();
PlainAuth.register();

let encoded_passwd = GOOD_PASSWD;
const fetch_callback = (
    username: string
): Promise<string> => {
    return new Promise<string>( (resolve, reject) => {
        resolve( encoded_passwd );
    });
};
const update_callback = (
    username: string
    ,passwd: string
): Promise<void> => {
    return new Promise<void>( (resolve, reject) => {
        encoded_passwd = passwd;
        resolve();
    });
};
const add_user_callback = (
    username: string
    ,passwd: string
): Promise<void> => {
    return new Promise<void>( (resolve, reject) => {
        // Ignore
        resolve();
    });
};


const castle = new Castle.Castellated(
    "bcrypt"
    ,"10"
    ,fetch_callback
    ,update_callback
    ,add_user_callback
);
castle
    .match( USERNAME, BAD_PASSWD )
    .then( (is_matched) => {
        Tap.ok(! is_matched, "Password matched" );
    })
    .then( () => {
        Tap.ok( encoded_passwd.match( /^ca571e-v1-plain/ )
            ,"Password did not change encoding" );
    });
