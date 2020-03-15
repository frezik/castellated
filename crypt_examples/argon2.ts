import * as Argon from "argon2";

// Parameters made up for testing's sake. Don't necessarily recommend 
// using these for any actual purpose.
const time_cost = 3;
const memory_cost = 64 * 1024;
const parallelism = 2;
const argon_type = Argon.argon2i;


const incoming_data = process.argv[2];
Argon
    .hash( incoming_data, {
        timeCost: time_cost
        ,memoryCost: memory_cost
        ,parallelism: parallelism
        ,type: argon_type
    })
    .then( (hash) => {
        console.log( hash );
    });
