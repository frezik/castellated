import * as AuthPlaintext from './auth/plaintext';


const CASTLE_STR_PREFIX = "ca571e";
const CASTLE_STR_VERSION = 1;
const CASTLE_STR_SEP = "-";
const CASTLE_STR_REGEX = new RegExp([
    "^", "(", CASTLE_STR_PREFIX, ")"
    ,CASTLE_STR_SEP, "v(", CASTLE_STR_VERSION, ")"
    ,CASTLE_STR_SEP, "([^\\", CASTLE_STR_SEP, "]+)" // Crypt type
    ,CASTLE_STR_SEP, "([^\\", CASTLE_STR_SEP, "]+)" // Crypt args
    ,CASTLE_STR_SEP, "(.*)" // Password data
    ,"$"
].join( "" ));


export type AuthCallback = (
    args_str: string
) => Authenticator;

let AUTH_BY_TYPE: object = {};

export function registerAuthenticator(
    name: string
    ,auth_callback: AuthCallback
): void
{
    AUTH_BY_TYPE[name] = auth_callback;
}

registerAuthenticator( AuthPlaintext.AUTH_NAME,
    AuthPlaintext.register() );


export function isMatch(
    str1: string
    ,str2: string
): boolean
{
    // Implement a constant-time algorithm for matching strings in 
    // order to prevent timing attacks. Failing fast is OK for length 
    // mismatch.
    if( str1.length != str2.length ) {
        return false;
    }

    let is_match = true;
    for( let i = 0; i < str1.length; i++ ) {
        if( str1.charAt( i ) != str2.charAt( i ) ) {
            is_match = false;
        }
    }

    return is_match;
}


type fetchPasswdCallbackType = (
    userame: string
) => Promise<string>;

type updatePasswdCallbackType = (
    username: string
    ,passwd: string
) => Promise<void>;


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

        const matches = this.orig_str.match( CASTLE_STR_REGEX );
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
        if( AUTH_BY_TYPE[crypt_type] ) {
            let auth_callback = AUTH_BY_TYPE[crypt_type];
            let auth = auth_callback( crypt_args);
            return auth;
        }
        else {
            throw `Could not find authenticator for crypt type "${crypt_type}"`;
        }
    }
}

export class Castellated
{
    private auth_preferred_type: string;
    private auth_args_string: string;
    private fetch_passwd_callback: fetchPasswdCallbackType;
    private update_passwd_callback: updatePasswdCallbackType;

    constructor(
        auth_preferred_type: string
        ,auth_args_string: string
        ,fetch_passwd_callback: fetchPasswdCallbackType
        ,update_passwd_callback: updatePasswdCallbackType
    )
    {
        this.auth_preferred_type = auth_preferred_type;
        this.auth_args_string = auth_args_string;
        this.fetch_passwd_callback = fetch_passwd_callback;
        this.update_passwd_callback = update_passwd_callback;
    }

    match(
        username: string
        ,passwd: string
    ): Promise<boolean>
    {
        return new Promise<boolean>( (resolve, reject) => {
            this.fetch_passwd_callback( username ).then(
                (correct_passwd) => {
                    const parsed_passwd = new PasswordString(
                        correct_passwd
                    );
                    const auth = parsed_passwd.auth;

                    if( auth.isMatch( passwd, parsed_passwd ) ) {
                        // TODO if not on preferred type, change it
                        resolve( true );
                    }
                    else {
                        resolve( false );
                    }
                }
            );
        });
    }

    addUser(
    ): Promise<void>
    {
        return new Promise<void>( (resolve, reject) => {
            // TODO
            resolve();
        });
    }
}

export interface Authenticator
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: PasswordString
    ): boolean;
}
