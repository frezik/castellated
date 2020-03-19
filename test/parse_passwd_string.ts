import Castle from '../src/castellated';
import Password from '../src/password_string';
import * as Tap from 'tap';


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


const passwd = "ca571e-v1-mock-plain-secretpass";
const parser = new Password( passwd );
const auth = parser.auth;

Tap.ok( auth, "Got authenticator" );
