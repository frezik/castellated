import * as Castellated from '../index';
import * as Tap from 'tap';

const plain = new Castellated.PlaintextAuth( "foobar" );
Tap.ok( plain.isMatch( "foobar" ), "Password matches" );
Tap.ok(! plain.isMatch( "barfoo" ), "Bad password doesn't match" );
