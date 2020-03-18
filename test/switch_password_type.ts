import * as Castle from '../index';
import BcryptAuth from '../src/auth/bcrypt';
import PlainAuth from '../src/auth/plaintext';
import * as Tap from 'tap';

const USERNAME = "foo";
const GOOD_PASSWD = "ca571e-v1-plain-plain-secretpass";
const GOOD_PASSWD_UNENCODED = "secretpass";

Tap.plan( 3 );
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
    .match( USERNAME, GOOD_PASSWD_UNENCODED )
    .then( (is_matched) => {
        Tap.ok( is_matched, "Password matched" );
    })
    .then( () => {
        Tap.ok( encoded_passwd.match( /^ca571e-v1-bcrypt/ )
            ,"Stored password changed encoding" );
        return castle.match( USERNAME, GOOD_PASSWD_UNENCODED );
    })
    .then( (is_matched) => {
        Tap.ok( is_matched, "Reencoded password still matches" );
    });
