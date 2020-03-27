import Authenticator from './authenticator';
import Castle from './castellated';


/**
 * Holds a password string that's been encoded into the Castellated format.
 */
export default class PasswordString
{
    /**
     * A string holding the name of the exception that will be thrown for 
     * strings that don't match the expected format.
     */
    static PASSWORD_STRING_FORMATTING_EXCEPTION
        = "PasswordStringFormattingException";

    /**
     * The original formatted string.
     */
    orig_str: string;
    /**
     * The "ca571e" string.
     */
    prefix; string;
    /**
     * Version number, not including the leading "v"
     */
    version: string;
    /**
     * The short name of the encoding type, e.g. "bcrypt", "scrypt", etc.
     */
    crypt_type: string;
    /**
     * The argument string. The exact format is determined by the encoding 
     * type.
     */
    crypt_args: string;
    /**
     * The encoded password.
     */
    passwd_data: string;
    /**
     * The authenticator that matches with the given type.
     */
    auth: Authenticator;

    /**
     * @param str The full password string, which will be parsed and its fields stored here
     */
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


    /**
     * Returns the original string.
     */
    toString(): string
    {
        return this.orig_str;
    }

    /**
     * Takes a straight string (without the "ca571e-...") and builds it into 
     * a PasswordString.
     *
     * @param plain_password The raw password
     * @param encryption_type The encoding type to use, defaults to "plain"
     * @param encryption_args The encoding args string, defaults to "plain"
     * @returns A PasswordString object based on the args passed above
     */
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
