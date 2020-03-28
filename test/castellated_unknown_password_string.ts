import Castle from '../index';
import * as Tap from 'tap';

Tap.plan( 1 );

const USERNAME = "foo";
const GOOD_PASSWD = "ca571e-v1-whoknows-whocares-foobar";
const GOOD_PASSWD_UNENCODED = "foobar";

const fetch_callback = (
    username: string
): Promise<string> => {
    return new Promise<string>( (resolve, reject) => {
        resolve( GOOD_PASSWD );
    });
};
const update_callback = (
    username: string
    ,passwd: string
): Promise<void> => {
    return new Promise<void>( (resolve, reject) => {
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
    "bcrypt"
    ,"10"
    ,fetch_callback
    ,update_callback
    ,add_user_callback
);

castle
    .match( USERNAME, GOOD_PASSWD_UNENCODED )
    .then( (is_matched) => {
        Tap.fail( "Was supposed to fail with bad authenticator" );
    })
    .catch( (err) => {
        Tap.pass( "Failed with bad authenticator" );
    });
