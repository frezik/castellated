interface Authenticator
{
    isMatch(
        incoming_passwd: string
        ,stored_passwd: Password.PasswordString
    ): Promise<boolean>;

    sameAuth(
        passwd: Password.PasswordString
    ): boolean;

    encode(
        passwd: string
    ): Promise<Password.PasswordString>;
}

export default Authenticator;
