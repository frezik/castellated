import Auth from '../src/auth/argon2';
import Password from '../src/password_string';
import * as Tap from 'tap';

const ARGON2_ARGS_STRING = 't:3,m:65536,p:l,f:2i';

let is_fail = false;
try {
    const crypt = new Auth( ARGON2_ARGS_STRING );
}
catch( e ) {
    is_fail = true;
}
Tap.ok( is_fail, "Failed on bad 'p' param" );
