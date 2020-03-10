import Authenticator from './authenticator';
import * as Castle from './castellated';


export class PasswordString
{
    orig_str: string;
    prefix; string;
    version: string;
    crypt_type: string;
    crypt_args: string;
    passwd_data: string;
    auth: Authenticator;

    constructor(
        str: string
    ) {
        this.orig_str = str;

        const matches = this.orig_str.match( Castle.CASTLE_STR_REGEX );
        if( matches ) {
            this.prefix = matches[1];
            this.version = matches[2];
            this.crypt_type = matches[3];
            this.crypt_args = matches[4];
            this.passwd_data = matches[5];

            this.auth = this.getAuthByString(
                this.crypt_type
                ,this.crypt_args
            );
        }
    }


    toString(): string
    {
        return this.orig_str;
    }


    private getAuthByString(
        crypt_type: string
        ,crypt_args: string
    ): Authenticator
    {
        let auth_callback = Castle.getAuthByName( crypt_type );
        if( auth_callback ) {
            let auth = auth_callback( crypt_args);
            return auth;
        }
        else {
            throw `Could not find authenticator for crypt type "${crypt_type}"`;
        }
    }
}
