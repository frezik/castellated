import * as Castellated from '../castellated';
import * as Bcrypt from 'bcrypt';

export const AUTH_NAME = "bcrypt";


export class BcryptAuth
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: Castellated.PasswordString
    ): Promise<boolean>
    {
        const want_passwd = stored_passwd.passwd_data;
        return Bcrypt.compare( incoming_passwd, want_passwd );
    }
}


export function register(): Castellated.AuthCallback
{
    const builder = (
        args_str: string
    ): Castellated.Authenticator => {
        return new BcryptAuth();
    };
    return builder;
}
