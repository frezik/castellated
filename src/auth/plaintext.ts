import * as Castellated from '../castellated';


export class PlaintextAuth
{
    private expected_password: String;


    constructor(
        expected_password: String
    )
    {
        this.expected_password = expected_password;
    }

    isMatch(
        auth_data: String
    ): boolean
    {
        return Castellated.isMatch(
            this.expected_password
            ,auth_data
        );
    }
}
