import * as Crypto from 'crypto';


// Parameters made up for testing's sake. Don't necessarily recommend 
// using these for any actual purpose.
const salt_len_bytes = 16;
const keylen = 64;
const cost = 16384;
const block_size = 8;
const parallelism = 1;


const incoming_data = process.argv[2];
const salt_hex = Crypto
    .randomBytes( salt_len_bytes )
    .toString( 'hex' );
Crypto
    .scrypt( incoming_data, salt_hex, keylen, {
        // Typescript type mapping does not have the options 
        // mapped for 'cost', 'blockSize', or 'parallelization'.
        // Boo this API!
        N: cost
        ,r: block_size
        ,p: parallelism
    }, (err, res) => {
        let str = res.toString( 'hex' );
        console.log( `Salt (hex): ${salt_hex}` );
        console.log( `Encoded Passwd: ${str}` );
    });
