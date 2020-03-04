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
) => Promise<string>;


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
                    // TODO encode passwd

                    if( isMatch( correct_passwd, passwd ) ) {
                        // TODO if not on preferred type, change it
                        resolve( true );
                    }
                    else {
                        resolve( false );
                    }
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
}

export interface Authenticator
{
    isMatch(
        auth_data: string
    ): boolean;
}
