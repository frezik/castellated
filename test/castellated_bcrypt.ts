import * as Castle from '../index';
import * as Auth from '../src/auth/bcrypt';
import * as Tap from 'tap';

const USERNAME = "foo";
const GOOD_PASSWD = "ca571e-v1-bcrypt-10-$2b$10$wOWIkiks.tbbftwkJ81BNeuOtq631SzbsVOO7VAHf5ziH.edAAqJi"
const GOOD_PASSWD_UNENCODED = "foobar";
const BAD_PASSWD = "ca571e-v1-plain-plain-badpass";

Tap.plan( 2 );
Auth.register();

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


const castle = new Castle.Castellated(
    "bcrypt"
    ,"10"
    ,fetch_callback
    ,update_callback
    ,add_user_callback
);

Tap.test( "Good passwd", (Tap) => {
    castle
        .match( USERNAME, GOOD_PASSWD_UNENCODED )
        .then( (is_matched) => {
            Tap.ok( is_matched, "Password matched" );
            Tap.end();
        });
})
.then( (Tap) => {
    castle
        .match( USERNAME, BAD_PASSWD )
        .then( (is_matched) => {
            Tap.ok(! is_matched, "Password did not match" );
            Tap.end();
        });
});