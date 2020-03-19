import Castle from '../src/castellated';
import Password from '../src/password_string';
import * as Tap from 'tap';

Tap.plan( 1 );

class MockAuth
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: Password
    ): Promise<boolean>
    {
        return new Promise( (resolve, reject) => {
            resolve( true );
        });
    }

    sameAuth(
        passwd: Password
    ): boolean
    {
        return true;
    }

    encode(
        passwd: string
    ): Promise<Password>
    {
        return new Promise( (resolve, reject) => {
            resolve( new Password([
                Castle.CASTLE_STR_PREFIX
                ,"v" + Castle.CASTLE_STR_VERSION
                ,"mock"
                ,"mock"
                ,passwd
            ].join( Castle.CASTLE_STR_SEP )));
        });
    }
}
Castle.registerAuthenticator(
    "mock"
    ,(args_str: string) => {
        return new MockAuth();
    }
);


const passwd = "a571e-v1-mock-plain-secretpass";
try {
    const parser = new Password( passwd );
}
catch( e ) {
    Tap.pass( "Bad string threw an error" );
}
