import Authenticator from '../authenticator';
import Castellated from '../castellated';
import Password from '../password_string';

export const AUTH_NAME = "plain";


/**
 * A plaintext {@link Authenticator}. This is mostly for testing purposes, and 
 * you should never use this in anything that matters. Its lookup name is 
 * "plain" and its args string is also "plain".
 */
export default class PlaintextAuth
{
    static register(): void
    {
        Castellated.registerAuthenticator( AUTH_NAME,
            ( args_str: string ): Authenticator => {
                return new PlaintextAuth();
            }
        );
    }


    isMatch(
        incoming_passwd: string
        ,stored_passwd: Password
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
        passwd: Password
    ): boolean
    {
        return (AUTH_NAME == passwd.crypt_type);
    }

    encode(
        passwd: string
    ): Promise<Password>
    {
        const new_passwd = new Password([
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
