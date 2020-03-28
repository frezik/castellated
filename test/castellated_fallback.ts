import Castle from '../index';
import * as Tap from 'tap';

const USERNAME = "foo";
const GOOD_PASSWD = "ca571e-v1-plain-plain-secretpass";
const GOOD_PASSWD_UNENCODED = "secretpass";
const BAD_PASSWD = "barfoo";

Tap.plan( 4 );

let stored_passwd = GOOD_PASSWD_UNENCODED;
const fetch_callback = (
    username: string
): Promise<string> => {
    return new Promise<string>( (resolve, reject) => {
        resolve( stored_passwd );
    });
};
const update_callback = (
    username: string
    ,passwd: string
): Promise<void> => {
    return new Promise<void>( (resolve, reject) => {
        stored_passwd = passwd;
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


const castle = new Castle(
    "plain"
    ,"plain"
    ,fetch_callback
    ,update_callback
    ,add_user_callback
);
castle.setFallbackAuthenticator(
    (
        username: string
        ,passwd: string
    ): Promise<boolean> => {
        return new Promise( (result, reject) => {
            result( GOOD_PASSWD_UNENCODED == passwd );
        });
    }
);

castle
    .match( USERNAME, BAD_PASSWD )
    .then( (is_matched) => {
        Tap.ok(! is_matched, "Bad password not matched" );
    })
    .then( () => {
        Tap.equals( stored_passwd, GOOD_PASSWD_UNENCODED,
            "Stored password unchanged" );
    })
    .then( () => {
        return castle.match( USERNAME, GOOD_PASSWD_UNENCODED )
    })
    .then( (is_matched) => {
        Tap.ok( is_matched, "Password matched" );
    })
    .then( () => {
        Tap.equals( stored_passwd, GOOD_PASSWD, "Stored password set" );
    });
