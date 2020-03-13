import * as Castle from '../index';
import * as PlaintextAuth from '../src/auth/plaintext';
import * as Tap from 'tap';

const USERNAME = "foo";
const GOOD_PASSWD = "ca571e-v1-plain-plain-secretpass";
const GOOD_PASSWD_UNENCODED = "secretpass";

Tap.plan( 3 );
PlaintextAuth.register();


let stored_username = "";
let stored_passwd = "";
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
        stored_username = username;
        stored_passwd = passwd;
        resolve();
    });
};


const castle = new Castle.Castellated(
    "plain"
    ,"plain"
    ,fetch_callback
    ,update_callback
    ,add_user_callback
);

castle
    .addUser( USERNAME, GOOD_PASSWD_UNENCODED )
    .then( () => {
        Tap.equals( stored_username, USERNAME, "Username stored" );
        Tap.equals( stored_passwd, GOOD_PASSWD, "Password stored" );
    })
    .then( () => {
        return castle.match( USERNAME, GOOD_PASSWD_UNENCODED );
    })
    .then( (is_match) => {
        Tap.ok( is_match, "Matched password after creating user" );
    });
