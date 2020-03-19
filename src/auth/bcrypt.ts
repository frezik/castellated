import Authenticator from '../authenticator';
import Castellated from '../castellated';
import * as Bcrypt from 'bcrypt';
import * as Password from '../password_string';

export const AUTH_NAME = "bcrypt";


export default class BcryptAuth
{
    private orig_args_str: string;
    private rounds: number;

    constructor(
        args_str: string
    ) {
        this.orig_args_str = args_str;
        this.rounds = parseInt( args_str );
    }

    static register(): void
    {
        Castellated.registerAuthenticator( AUTH_NAME, 
            ( args_str: string): Authenticator => {
                return new BcryptAuth( args_str );
            }
        );
    }


    isMatch(
        incoming_passwd: string
        ,stored_passwd: Password.PasswordString
    ): Promise<boolean>
    {
        const want_passwd = stored_passwd.passwd_data;
        return Bcrypt.compare( incoming_passwd, want_passwd );
    }

    sameAuth(
        passwd: Password.PasswordString
    ): boolean
    {
        return (AUTH_NAME == passwd.crypt_type)
            && (passwd.crypt_args == this.orig_args_str);
    }

    encode(
        passwd: string
    ): Promise<Password.PasswordString>
    {
        return Bcrypt
            .hash( passwd, this.rounds )
            .then( (hash) => {
                const new_passwd = new Password.PasswordString([
                    Castellated.CASTLE_STR_PREFIX
                    ,"v" + Castellated.CASTLE_STR_VERSION
                    ,AUTH_NAME
                    ,this.orig_args_str
                    ,hash
                ].join( Castellated.CASTLE_STR_SEP ));

                return new Promise( (resolve, reject) => {
                    resolve( new_passwd );
                });
            });
    }
}
