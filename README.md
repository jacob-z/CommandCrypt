# CommandCrypt
Encrypt/Decrypt files from the command line.

CommandCrypt may be used to encrypt and decrypt files using AES 128 encryption 
right from the command line. Specify single files or whole directories.  
You can also give a directory where the processed files will be stored.
 
Example:
        The default options for CommandCrypt are to encrypt the files specified in
        the immediate command line arguments.  If a directory is provided, only the
        files in the first level of the directory will be encrypted.  The resulting
        files will be stored in the current directory:
 
                $ python CommandCrypt.py samplefile.txt
 
        Command line arguments enable more complex operations and decryption.
        Use "-d" or "--decrypt" to decrypt an encrypted file.
 
                $ python CommandCrypt.py -d ENCsamplefile.txt
 
        Use "-r" or "--recurse" to include files in subdirectories.
 
                S python CommandCrypt.py -r ./sampleDir
 
        A directory for output can be speficied with the "--dest" flag.
 
                $ python CommandCrypt.py samplefile.txt --dest ./resultDir
 
Attributes:
        SALT_BYTES (int): The number of bytes to be used when salting passwords.
        ITERATIONS (int): The number of times to apply the hash function to itself.
 
Todo:
        * Add padding to smaller files
        * Store encrypted files in the specified destination
        * Maintain or encode file hierarchy in encrypted files
