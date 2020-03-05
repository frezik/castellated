import * as Castle from '../src/castellated';
import * as Tap from 'tap';


class MockAuth
{
    args_str: string;

    constructor(
        args_str: string
    ) {
        this.args_str = args_str;
    }

    isMatch(
    ): boolean
    {
        return true;
    }
}
Castle.registerAuthenticator(
    "mock"
    ,( arg_str: string ) => {
        return new MockAuth( arg_str );
    }
);


const passwd = "ca571e-v1-mock-plain-secretpass";
const parser = new Castle.PasswordString( passwd );
const auth = parser.auth;

Tap.ok( auth, "Got authenticator" );
