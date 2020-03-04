import * as Castellated from '../castellated';


export class PlaintextAuth
{
    private expected_password: string;


    constructor(
        expected_password: string
    )
    {
        this.expected_password = expected_password;
    }

    isMatch(
        auth_data: string
    ): boolean
    {
        return Castellated.isMatch(
            this.expected_password
            ,auth_data
        );
    }
}
