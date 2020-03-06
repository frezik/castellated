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
