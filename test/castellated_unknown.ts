import Castle from '../index';
import * as Tap from 'tap';

const GOOD_PASSWD = "ca571e-v1-plain-plain-secretpass";

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


let is_fail = false;
try {
    const castle = new Castle(
        "whoknows"
        ,"whocares"
        ,fetch_callback
        ,update_callback
        ,add_user_callback
    );
}
catch( err ) {
    is_fail = true;
}
Tap.ok( is_fail, "Failed to look up bad authenticator" );
