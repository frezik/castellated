import * as Castle from '../index';
import * as Tap from 'tap';

const USERNAME = "foo";
const GOOD_PASSWD = "secretpass";
const BAD_PASSWD = "badpass";

Tap.plan( 2 );

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


const castle = new Castle.Castellated(
    "plaintext"
    ,""
    ,fetch_callback
    ,update_callback
);

Tap.test( "Good passwd", (Tap) => {
    castle
        .match( USERNAME, GOOD_PASSWD )
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
