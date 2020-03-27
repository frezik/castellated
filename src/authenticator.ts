/**
 * Authenticators implement an encoding type, e.g. scrypt, bcrypt, etc.
 */
interface Authenticator
{
    /**
     * Called when an incoming (plaintext) password needs to be matched 
     * against a stored (encoded) password.
     *
     * @param incoming_passwd The incoming plaintext password
     * @param stored_passwd The stored encoded password
     * @returns A promise that yields a boolean, showing if the password matched or not
     */
    isMatch(
        incoming_passwd: string
        ,stored_passwd: Password.PasswordString
    ): Promise<boolean>;

    /**
     * Checks if the given password string is the same kind of authenticator 
     * as you. This includes not just the name of the authenticator (like 
     * bcrypt), but also that all important parameters match.
     *
     * @param passwd The password string to check
     * @returns A boolean indicating if the authentication type is the same or not
     */
    sameAuth(
        passwd: Password.PasswordString
    ): boolean;

    /**
     * Encodes a plaintext password into an encoded password.
     *
     * @param passwd The plaintext password to check
     * @returns A promise that yields a {@link PasswordString} for the encoded password
     */
    encode(
        passwd: string
    ): Promise<Password.PasswordString>;
}

export default Authenticator;
