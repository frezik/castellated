import Castle from './src/castellated';
export default Castle;

// Register all the default authenticators
Castle.Argon2.register();
Castle.Bcrypt.register();
Castle.Plaintext.register();
Castle.Scrypt.register();
