import Authenticator from '../authenticator';
import Castellated from '../castellated';
import * as Argon2 from 'argon2';
import Password from '../password_string';

const AUTH_NAME = "argon2";


type argonArgs = {
    time_cost: number
    ,memory_cost: number
    ,parallelism: number
    ,argon_type: string
};

/**
 * An {@link Authenticator} for argon2. Its lookup name is "argon2", and its 
 * args string looks like this:
 * 
 * `t:3,m:65536,p:2,f:2i`
 *
 * This is a set of name:value pairs separted by commas. The params are:
 *
 * * **t**: The time cost, which increases the number of iterations
 * * **m**: The memory cost, in KiB
 * * **p**: Number of threads (parallelism)
 * * **f**: Argon2 function type. Valid values are "2i", "2d", and "2id".
 *
 * Since we're doing password hasing, the function type will almost always be 
 * "2i". For more information, see:
 *
 * https://github.com/ranisalt/node-argon2/wiki/Options
 */
export default class Argon2Auth
{
    private orig_args_str: string;
    private time_cost: number;
    private memory_cost: number;
    private parallelism: number;
    private argon_type: string;

    constructor(
        args_str: string
    ) {
        this.orig_args_str = args_str;

        const args = this.parseArgString( args_str );
        this.time_cost = args.time_cost;
        this.memory_cost = args.memory_cost;
        this.parallelism = args.parallelism;
        this.argon_type = args.argon_type;
    }


    static register(): void
    {
        Castellated.registerAuthenticator( AUTH_NAME, 
            ( args_str: string): Authenticator => {
                return new Argon2Auth( args_str );
            }
        );
    }


    isMatch(
        incoming_passwd: string
        ,stored_passwd: Password
    ): Promise<boolean>
    {
        const want_passwd = stored_passwd.passwd_data;
        return Argon2.verify( want_passwd, incoming_passwd );
    }

    sameAuth(
        passwd: Password
    ): boolean
    {
        const args_str = passwd.crypt_args;
        const args = this.parseArgString( args_str );
        const argon_type = args.argon_type;

        return (AUTH_NAME == passwd.crypt_type)
            && (this.time_cost == args.time_cost)
            && (this.memory_cost == args.memory_cost)
            && (this.parallelism == args.parallelism)
            && (this.argon_type == argon_type);
    }

    encode(
        passwd: string
    ): Promise<Password>
    {
        const args = {
            time_cost: this.time_cost
            ,memory_cost: this.memory_cost
            ,parallelism: this.parallelism
            ,argon_type: this.argon_type
        };
        return Argon2.hash( passwd, args ).then( (hash) => {
            return new Promise( (resolve, reject) => {
                const encoded_args = this.encodeArgs( args );
                const passwd_string = Password.buildFromPlain(
                    hash
                    ,AUTH_NAME
                    ,encoded_args
                );
                resolve( passwd_string );
            });
        });
    }

    private parseArgString(
        arg_str: string
    ): argonArgs
    {
        const time_cost = arg_str.match( /t:\s*(\d+)/ );
        const memory_cost = arg_str.match( /m:\s*(\d+)/ );
        const parallelism = arg_str.match( /p:\s*(\d+)/ );
        const argon_type = arg_str.match( /f:\s*(\w+)/ );

        if(! time_cost ) throw `Could not parse 't' param in argon2 string: ${arg_str}`;
        if(! memory_cost ) throw `Could not parse 'm' param in argon2 string: ${arg_str}`;
        if(! parallelism ) throw `Could not parse 'p' param in argon2 string: ${arg_str}`;
        if(! argon_type ) throw `Could not parse 'f' param in argon2 string: ${arg_str}`;


        return {
            time_cost: parseInt( time_cost[1] )
            ,memory_cost: parseInt( memory_cost[1] )
            ,parallelism: parseInt( parallelism[1] )
            ,argon_type: argon_type[1]
        };
    }

    private encodeArgs(
        args: argonArgs
    ): string
    {
        const arg_str = [
            't:' + args.time_cost
            ,'m:' + args.memory_cost
            ,'p:' + args.parallelism
            ,'f:' + args.argon_type
        ].join( "," );
        return arg_str;
    }

    private argonTypeStringToID(
        type_str: string
    ): number
    {
        const type_id = 
            ("2i" == type_str) ? Argon2.argon2i :
            ("2d" == type_str) ? Argon2.argon2d :
            ("2id" == type_str) ? Argon2.argon2id :
            null;
        if(! type_id) {
            throw "Unknown argon2 hash function ID: " + this.argon_type;
        }

        return type_id;
    }
}
