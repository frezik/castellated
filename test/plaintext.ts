import * as Auth from '../src/auth/plaintext';
import * as Tap from 'tap';

const plain = new Auth.PlaintextAuth( "foobar" );
Tap.ok( plain.isMatch( "foobar" ), "Password matches" );
Tap.ok(! plain.isMatch( "barfoo" ), "Bad password doesn't match" );
