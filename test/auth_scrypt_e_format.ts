import Auth from '../src/auth/scrypt';
import * as Tap from 'tap';

Tap.plan( 1 );

const SCRYPT_ARGS_STRING = 'c:16384,b:8,p:1,s:16,k:64,e:/,l:5476558450e3f2d9818d81b61ed570e1';

let is_failed = false;
try {
    const crypt = new Auth( SCRYPT_ARGS_STRING );
}
catch {
    is_failed = true;
}
Tap.ok( is_failed, "Failed on 'e' parameter" );
