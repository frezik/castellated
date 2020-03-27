import Authenticator from './authenticator';
import Password from './password_string';
import AuthArgon2 from './auth/argon2';
import AuthBcrypt from './auth/bcrypt';
import AuthPlaintext from './auth/plaintext';
import AuthScrypt from './auth/scrypt';




export type AuthCallback = (
    args_str: string
) => Authenticator;

let AUTH_BY_TYPE: object = {};


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


export default class Castellated
{
    static CASTLE_STR_PREFIX = "ca571e";
    static CASTLE_STR_VERSION = 1;
    static CASTLE_STR_SEP = "-";

    /**
     * A regex that can be used to match castellated strings. When matched, 
     * it will have the following capture data:
     * * "ca571e" prefix
     * * Version number, without the leading "v"
     * * Encoding name
     * * Encoding args
     * * Password data
     */
    static CASTLE_STR_REGEX = new RegExp([
        "^", "(", Castellated.CASTLE_STR_PREFIX, ")"
        ,Castellated.CASTLE_STR_SEP, "v("
            ,Castellated.CASTLE_STR_VERSION
        ,")"
        ,Castellated.CASTLE_STR_SEP, "([^\\"
            ,Castellated.CASTLE_STR_SEP
        ,"]+)" // Crypt type
        ,Castellated.CASTLE_STR_SEP, "([^\\"
            ,Castellated.CASTLE_STR_SEP
        ,"]+)" // Crypt args
        ,Castellated.CASTLE_STR_SEP, "(.*)" // Password data
        ,"$"
    ].join( "" ), 'm' );

    static Argon2 = AuthArgon2;
    static Bcrypt = AuthBcrypt;
    static Plaintext = AuthPlaintext;
    static Scrypt = AuthScrypt;

    private auth_preferred_type: string;
    private auth_args_string: string;
    private auth_preferred: Authenticator;
    private fetch_passwd_callback: fetchPasswdCallbackType;
    private update_passwd_callback: updatePasswdCallbackType;
    private fallback_authenticator: fallbackAuthenticatorCallbackType;
    private add_user_callback: addUserCallbackType;

    /**
     * @param auth_preferred_type The name of the authenticator you prefer
     * @param auth_args_string The args string for your preferred authenticator
     * @param fetch_passwd_callback Called for fetching a password for a given user
     * @param update_passwd_callback Called for updating a password for a given user
     * @param add_user_callback Called for adding a new user
     */
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

    /**
     * Registers an authenticator under the given name.
     * 
     * @param name The short name of the authenticator
     * @param auth_callback Called to get the authenticator as an instantiated object
     */
    static registerAuthenticator(
        name: string
        ,auth_callback: AuthCallback
    ): void
    {
        AUTH_BY_TYPE[name] = auth_callback;
    }

    /**
     * Fetches a given authenticator by its short name.
     *
     * @param name The short name of the authenticator
     * @returns The instantiated authenticator object
     */
    static getAuthByName(
        name: string
    ): AuthCallback
    {
        return AUTH_BY_TYPE[name];
    }

    /**
     * Helper function for matching password strings in a constant-time 
     * algorithm. To prevent timing attacks, use this to match passwords 
     * instead of something like "passwd1 == passwd2".
     */
    static isMatch(
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



    /**
     * Checks if the given username and plaintext password matches what is 
     * stored for that user.
     *
     * If the stored password does not match the castellated string format, and 
     * a fallback authenticator was set in {@link setFallbackAuthenticator}, 
     * then the fallback authenticator will be tried.
     *
     * @param username The username to check
     * @param passwd The password to check
     * @returns A promise that yields a boolean, saying if the password matched or not
     */
    match(
        username: string
        ,passwd: string
    ): Promise<boolean>
    {
        return new Promise<boolean>( (resolve, reject) => {
            this.fetch_passwd_callback( username ).then(
                (correct_passwd) => {
                    try {
                        const parsed_passwd = new Password(
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

    /**
     * Adds a user to the storage.
     *
     * @param username The username to store
     * @param password The plaintext password to encode and then store
     * @returns A promise that resolves when storage is complete.
     */
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

    /**
     * Sets a fallback authenticator, which will be used for password strings 
     * that were stored, but not in castellated format. This is useful for 
     * migrating existing systems into Castellated.
     *
     * @param auth The fallback callback
     */
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
                .then( (reencoded_passwd: Password ) => {
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
        ,parsed_passwd: Password
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
