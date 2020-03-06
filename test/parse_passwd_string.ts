import * as Castle from '../src/castellated';
import * as Tap from 'tap';


class MockAuth
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: Castle.PasswordString
    ): Promise<boolean>
    {
        return new Promise( (resolve, reject) => {
            resolve( true );
        });
    }

    sameAuth(
        passwd: Castle.PasswordString
    ): boolean
    {
        return true;
    }

    encode(
        passwd: string
    ): Promise<Castle.PasswordString>
    {
        return new Promise( (resolve, reject) => {
            resolve( new Castle.PasswordString([
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


const passwd = "ca571e-v1-mock-plain-secretpass";
const parser = new Castle.PasswordString( passwd );
const auth = parser.auth;

Tap.ok( auth, "Got authenticator" );
