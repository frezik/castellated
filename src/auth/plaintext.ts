import * as Castellated from '../castellated';

export const AUTH_NAME = "plain";


export class PlaintextAuth
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: Castellated.PasswordString
    ): boolean
    {
        return Castellated.isMatch(
            incoming_passwd
            ,stored_passwd.passwd_data
        );
    }
}


export function register(): Castellated.AuthCallback
{
    const builder = (
        args_str: string
    ): Castellated.Authenticator => {
        return new PlaintextAuth();
    };
    return builder;
}
