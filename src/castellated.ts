import Authenticator from './authenticator';
import * as Password from './password_string';


export const CASTLE_STR_PREFIX = "ca571e";
export const CASTLE_STR_VERSION = 1;
export const CASTLE_STR_SEP = "-";
export const CASTLE_STR_REGEX = new RegExp([
    "^", "(", CASTLE_STR_PREFIX, ")"
    ,CASTLE_STR_SEP, "v(", CASTLE_STR_VERSION, ")"
    ,CASTLE_STR_SEP, "([^\\", CASTLE_STR_SEP, "]+)" // Crypt type
    ,CASTLE_STR_SEP, "([^\\", CASTLE_STR_SEP, "]+)" // Crypt args
    ,CASTLE_STR_SEP, "(.*)" // Password data
    ,"$"
].join( "" ), 'm' );


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

export function getAuthByName(
    name: string
): AuthCallback
{
    return AUTH_BY_TYPE[name];
}


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

type fallbackAuthenticatorCallbackType = (
    username: string
    ,passwd: string
) => Promise<boolean>;

type addUserCallbackType = (
    username: string
    ,passwd: string
) => Promise<void>;


export class Castellated
{
    private auth_preferred_type: string;
    private auth_args_string: string;
    private auth_preferred: Authenticator;
    private fetch_passwd_callback: fetchPasswdCallbackType;
    private update_passwd_callback: updatePasswdCallbackType;
    private fallback_authenticator: fallbackAuthenticatorCallbackType;
    private add_user_callback: addUserCallbackType;

    constructor(
        auth_preferred_type: string
        ,auth_args_string: string
        ,fetch_passwd_callback: fetchPasswdCallbackType
        ,update_passwd_callback: updatePasswdCallbackType
        ,add_user_callback: addUserCallbackType
    )
    {
        this.auth_preferred_type = auth_preferred_type;
        this.auth_args_string = auth_args_string;
        this.fetch_passwd_callback = fetch_passwd_callback;
        this.update_passwd_callback = update_passwd_callback;
        this.add_user_callback = add_user_callback;

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
                    try {
                        const parsed_passwd = new Password.PasswordString(
                            correct_passwd
                        );
                        return this.runParsedPassword(
                            username
                            ,parsed_passwd
                            ,passwd
                        );
                    }
                    catch( err ) {
                        if( (Password
                            .PASSWORD_STRING_FORMATTING_EXCEPTION
                            == err.name 
                        ) && this.fallback_authenticator ) {
                            // String was malformatted, try the fallback
                            // authenticator since we have one
                            return this.runFallbackAuthenticator(
                                username
                                ,passwd
                            );
                        }
                        else {
                            throw err;
                        }
                    }
                }
            )
            .then( (is_ok) => {
                resolve( is_ok );
            });
        });
    }

    addUser(
        username: string
        ,password: string
    ): Promise<void>
    {
        return new Promise<void>( (resolve, reject) => {
            const password_string = Password.buildFromPlain(
                password
            );
            this
                .add_user_callback(
                    username
                    ,password_string.toString()
                )
                .then( () => {
                    resolve();
                });
        });
    }

    setFallbackAuthenticator(
        auth: fallbackAuthenticatorCallbackType
    ): void
    {
        this.fallback_authenticator = auth;
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
                .then( (reencoded_passwd: Password.PasswordString ) => {
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

    private runParsedPassword(
        username: string
        ,parsed_passwd: Password.PasswordString
        ,incoming_passwd: string
    ): Promise<boolean>
    {
        const auth = parsed_passwd.auth;
        return auth
            .isMatch( incoming_passwd, parsed_passwd )
            .then( (is_match) => {
                if( is_match
                    && (! this.auth_preferred.sameAuth( parsed_passwd ) )
                ) {
                    return this.reencode(
                        username
                        ,incoming_passwd
                    );
                }
                else {
                    return new Promise( (resolve) => {
                        resolve( is_match );
                    });
                }
            });
    }

    private runFallbackAuthenticator(
        username: string
        ,incoming_passwd: string
    ): Promise<boolean>
    {
        return new Promise( (resolve, reject) => {
            this.fallback_authenticator(
                username
                ,incoming_passwd
            )
            .then( (is_match) => {
                if( is_match ) {
                    return this.reencode(
                        username
                        ,incoming_passwd
                    );
                }
                else {
                    return new Promise( (resolve, reject) => {
                        resolve( false );
                    });
                }
            })
            .then( (is_ok: boolean) => {
                resolve( is_ok );
            });
        });
    }
}
