import * as AuthPlaintext from './auth/plaintext';
import * as AuthBcrypt from './auth/bcrypt';


export const CASTLE_STR_PREFIX = "ca571e";
export const CASTLE_STR_VERSION = 1;
export const CASTLE_STR_SEP = "-";
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
registerAuthenticator( AuthBcrypt.AUTH_NAME,
    AuthBcrypt.register() );


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
    private auth_preferred: Authenticator;
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

        if( AUTH_BY_TYPE[this.auth_preferred_type] ) {
            const callback = AUTH_BY_TYPE[ this.auth_preferred_type ];
            this.auth_preferred = callback(
                this.auth_args_string
            );
        }
        else {
            throw `Could not find authenticator for crypt type "${this.auth_preferred_type }"`;
        }
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

                    return auth
                        .isMatch( passwd, parsed_passwd )
                        .then( (is_match) => {
                            if( is_match && (! this.auth_preferred
                                .sameAuth( parsed_passwd )
                            )) {
                                return this.reencode( 
                                    username
                                    ,passwd
                                );
                            }
                            else {
                                return new Promise( (new_resolve) => {
                                    new_resolve( is_match );
                                });
                            }
                        });
                })
                .then( (result: boolean) => {
                    resolve( result );
                });
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

    private reencode(
        username: string
        ,passwd: string
    ): Promise<boolean>
    {
        return new Promise( (resolve, reject) => {
            this
                .auth_preferred
                .encode( passwd )
                .then( (reencoded_passwd: PasswordString ) => {
                    return this.update_passwd_callback(
                        username
                        ,reencoded_passwd.orig_str
                    );
                })
                .then( () => {
                    resolve( true );
                });
        });
    }
}

export interface Authenticator
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: PasswordString
    ): Promise<boolean>;

    sameAuth(
        passwd: PasswordString
    ): boolean;

    encode(
        passwd: string
    ): Promise<PasswordString>;
}
