import * as Castle from '../index';
import * as PlaintextAuth from '../src/auth/plaintext';
import * as Tap from 'tap';

const USERNAME = "foo";
const GOOD_PASSWD = "ca571e-v1-plain-plain-secretpass";
const GOOD_PASSWD_UNENCODED = "secretpass";

Tap.plan( 2 );
PlaintextAuth.register();

let stored_passwd = "";
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

const castle = new Castle.Castellated(
    "plain"
    ,"plain"
    ,fetch_callback
    ,update_callback
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
    .match( USERNAME, GOOD_PASSWD_UNENCODED )
    .then( (is_matched) => {
        Tap.ok( is_matched, "Password matched" );
    })
    .then( () => {
        Tap.equals( stored_passwd, GOOD_PASSWD, "Stored password set" );
    });
