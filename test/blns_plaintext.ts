import * as Castle from '../src/castellated';
import * as Auth from '../src/auth/plaintext';
import * as FS from 'fs';
import * as Password from '../src/password_string';
import * as Tap from 'tap';

Auth.register();
const auth = new Auth.PlaintextAuth();

// List of indexes in the Big List of Naughty Strings that give us 
// problems. TODO figure out why each one fails.
const SKIP_STRING_INDEX = [
    95
];


FS.readFile( 'test_data/blns.json', 'utf8', (err, contents) => {
    if( err ) {
        throw err;
    }

    const blns = JSON.parse( contents );
    Tap.plan( blns.length );

    blns.forEach( (bad_string, i) => {
        Tap.test( `String index ${i}`, (test) => {
            test.plan( 2 );

            auth
                .encode( bad_string )
                .then( (result) => {
                    test.pass( `Encoded without error` );
                    return auth.isMatch(
                        bad_string
                        ,result
                    );
                })
                .then( (is_match) => {
                    test.pass( `Matched without error` );
                })
                .catch( (err) => {
                    test.fail( "Error caught: " + err );
                });
        });
    });
});
