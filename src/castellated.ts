export function isMatch(
    str1: String
    ,str2: String
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

export interface Authenticator
{
    isMatch(
        auth_data: String
    ): boolean;
}
