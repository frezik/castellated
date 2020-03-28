import Authenticator from '../authenticator';
import Castellated from '../castellated';
import * as Crypto from 'crypto';
import Password from '../password_string';

export const AUTH_NAME = "scrypt";


export enum SaltEncoding {
    hex = "h"
}

type scryptArgs = {
    salt_len: number
    ,salt: string
    ,salt_encoding: SaltEncoding
    ,key_len: number
    ,cost: number
    ,block_size: number
    ,parallelism: number
};
/**
 * An {@link Authenticator} for scrypt. Its lookup name is "scrypt", and its 
 * args string looks like this:
 *
 * `c:16384,b:8,p:1,s:16,k:64,e:h,l:5476558450e3f2d9818d81b61ed570e1`
 *
 * This is a set of name:value pairs separted by commas. The params are:
 *
 * * **c**: Cost
 * * **b**: Block size
 * * **p**: Parallelization
 * * **s**: Salt length in bytes
 * * **k**: Key length
 * * **e**: Salt encoding. "h" specifies hex
 * * **l**: The salt itself, encoded according to the "e" parameter
 *
 * Having the salt in the args string makes scrypt a bit of an oddball. Most 
 * other Authenticators handle salt on their own, but implementation details 
 * required the salt to appear here. Note that the `sameAuth()` method does 
 * *not* check the salt ("l") parameter for its purposes.
 */
export default class ScryptAuth
{
    private orig_args_str: string;
    private salt_len: number;
    private salt: string;
    private salt_encoding: SaltEncoding;
    private key_len: number;
    private cost: number;
    private block_size: number;
    private parallelism: number;

    constructor(
        args_str: string
    ) {
        this.orig_args_str = args_str;

        const args = this.parseArgString( args_str );
        this.salt_len = args.salt_len;
        this.salt = args.salt;
        this.salt_encoding = args.salt_encoding;
        this.key_len = args.key_len;
        this.cost = args.cost;
        this.block_size = args.block_size;
        this.parallelism = args.parallelism;
    }

    static register(): void
    {
        Castellated.registerAuthenticator( AUTH_NAME, 
            ( args_str: string): Authenticator => {
                return new ScryptAuth( args_str );
            }
        );
    }


    isMatch(
        incoming_passwd: string
        ,stored_passwd: Password
    ): Promise<boolean>
    {
        const args = this.parseArgString(
            stored_passwd.crypt_args
        );
        const cost = args.cost;
        const block_size = args.block_size;
        const parallelism = args.parallelism;
        const salt = args.salt;
        const want_passwd = stored_passwd.passwd_data;
        const key_len = args.key_len;

        return new Promise( (resolve, reject) => {
            Crypto
                .scrypt( incoming_passwd, salt, key_len, {
                    // Typescript type mapping does not have the options 
                    // mapped for 'cost', 'blockSize', or 
                    // 'parallelization'. Boo this API!
                    N: cost
                    ,r: block_size
                    ,p: parallelism
                }, (err, res) => {
                    const str = res.toString( 'hex' );
                    const is_match = Castellated.isMatch(
                        str
                        ,want_passwd
                    );
                    resolve( is_match );
                });
        });
    }

    sameAuth(
        passwd: Password
    ): boolean
    {
        const args_str = passwd.crypt_args;
        const args = this.parseArgString( args_str );

        return (AUTH_NAME == passwd.crypt_type)
            && (this.salt_len == args.salt_len)
            // We don't check salt, as that's not part of the 
            // params you would configure
            && (this.salt_encoding == args.salt_encoding)
            && (this.key_len == args.key_len)
            && (this.cost == args.cost)
            && (this.block_size == args.block_size)
            && (this.parallelism == args.parallelism)
    }

    encode(
        passwd: string
    ): Promise<Password>
    {
        const cost = this.cost;
        const block_size = this.block_size;
        const parallelism = this.parallelism;
        const salt_len = this.salt_len;
        const salt_encoding = this.salt_encoding;
        const key_len = this.key_len;

        // TODO handle salt_encoding
        const salt_hex = Crypto
            .randomBytes( salt_len )
            .toString( 'hex' );
        return new Promise( (resolve, reject) => {
            Crypto
                .scrypt( passwd, salt_hex, key_len, {
                    // Typescript type mapping does not have the options 
                    // mapped for 'cost', 'blockSize', or 
                    // 'parallelization'. Boo this API!
                    N: cost
                    ,r: block_size
                    ,p: parallelism
                }, (err, res) => {
                    const new_passwd = new Password([
                        Castellated.CASTLE_STR_PREFIX
                        ,"v" + Castellated.CASTLE_STR_VERSION
                        ,AUTH_NAME
                        ,this.orig_args_str
                        ,passwd
                    ].join( Castellated.CASTLE_STR_SEP ));
                    resolve( new_passwd );
                });
        });
    }

    private parseArgString(
        arg_str: string
    ): scryptArgs
    {
        const salt_len = arg_str.match( /s:\s*(\d+)/ );
        const salt = arg_str.match( /l:\s*([\dA-Fa-f]+)/ );
        const salt_encoding = arg_str.match( /e:\s*(\w+)/ );
        const key_len = arg_str.match( /k:\s*(\d+)/ );
        const cost = arg_str.match( /c:\s*(\d+)/ );
        const block_size = arg_str.match( /b:\s*(\d+)/ );
        const parallelism = arg_str.match( /p:\s*(\d+)/ );

        if(! salt_len ) throw `Could not parse 's' param in scrypt string: ${arg_str}`;
        if(! salt ) throw `Could not parse 'l' param in scrypt string: ${arg_str}`;
        if(! salt_encoding ) throw `Could not parse 'e' param in scrypt string: ${arg_str}`;
        if(! key_len ) throw `Could not parse 'k' param in scrypt string: ${arg_str}`;
        if(! cost ) throw `Could not parse 'c' param in scrypt string: ${arg_str}`;
        if(! block_size ) throw `Could not parse 'b' param in scrypt string: ${arg_str}`;
        if(! parallelism ) throw `Could not parse 'p' param in scrypt string: ${arg_str}`;

        return {
            salt_len: parseInt( salt_len[1] )
            ,salt: salt[1]
            ,salt_encoding: SaltEncoding[salt_encoding[1]]
            ,key_len: parseInt( key_len[1] )
            ,cost: parseInt( cost[1] )
            ,block_size: parseInt( block_size[1] )
            ,parallelism: parseInt( parallelism[1] )
        };
    }

    private encodeArgs(
        args: scryptArgs
    ): string
    {
        const arg_str = [
            's:' + args.salt_len
            ,'l:' + args.salt
            ,'e:' + args.salt_encoding
            ,'k:' + args.key_len
            ,'c:' + args.cost
            ,'b:' + args.block_size
            ,'p:' + args.parallelism
        ].join( "," );
        return arg_str;
    }
}
