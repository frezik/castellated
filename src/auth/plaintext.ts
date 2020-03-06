import * as Castellated from '../castellated';

export const AUTH_NAME = "plain";


export class PlaintextAuth
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: Castellated.PasswordString
    ): Promise<boolean>
    {
        return new Promise( (resolve, reject) => {
            const result = Castellated.isMatch(
                incoming_passwd
                ,stored_passwd.passwd_data
            );
            resolve( result );
        });
    }

    sameAuth(
        passwd: Castellated.PasswordString
    ): boolean
    {
        return (AUTH_NAME == passwd.crypt_type);
    }

    encode(
        passwd: string
    ): Promise<Castellated.PasswordString>
    {
        const new_passwd = new Castellated.PasswordString([
            Castellated.CASTLE_STR_PREFIX
            ,"v" + Castellated.CASTLE_STR_VERSION
            ,AUTH_NAME
            ,AUTH_NAME
            ,passwd
        ].join( Castellated.CASTLE_STR_SEP ));

        return new Promise( (resolve, reject) => {
            resolve( new_passwd );
        });
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
