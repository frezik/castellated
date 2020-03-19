import Authenticator from './authenticator';
import Castle from './castellated';


export default class PasswordString
{
    static PASSWORD_STRING_FORMATTING_EXCEPTION
        = "PasswordStringFormattingException";

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
        else {
            let err = new Error( `Castellated password string "${str}"`
                + ` is incorrectly formatted` );
            err.name = PasswordString.PASSWORD_STRING_FORMATTING_EXCEPTION;
            throw err;
        }
    }


    toString(): string
    {
        return this.orig_str;
    }

    static buildFromPlain(
        plain_passwd: string
        ,encryption_type = "plain"
        ,encryption_args = "plain"
    ): PasswordString
    {
        const full_string = [
            Castle.CASTLE_STR_PREFIX
            ,"v" + Castle.CASTLE_STR_VERSION
            ,encryption_type
            ,encryption_args
            ,plain_passwd
        ].join( Castle.CASTLE_STR_SEP );

        const parsed_string = new PasswordString( full_string );
        return parsed_string;
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
