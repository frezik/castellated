import Castle from '../src/castellated';
import * as Password from '../src/password_string';
import * as Tap from 'tap';


class MockAuth
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: Password.PasswordString
    ): Promise<boolean>
    {
        return new Promise( (resolve, reject) => {
            resolve( true );
        });
    }

    sameAuth(
        passwd: Password.PasswordString
    ): boolean
    {
        return true;
    }

    encode(
        passwd: string
    ): Promise<Password.PasswordString>
    {
        return new Promise( (resolve, reject) => {
            resolve( new Password.PasswordString([
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
const parser = new Password.PasswordString( passwd );
const auth = parser.auth;

Tap.ok( auth, "Got authenticator" );
