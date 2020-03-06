import * as bcrypt from 'bcrypt';

const ROUNDS = 10;


const incoming_data = process.argv[2];
bcrypt
    .hash( incoming_data, ROUNDS )
    .then( (hash) => {
        console.log( hash );
    });
