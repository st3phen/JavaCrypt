import java.io.*;
import java.util.*;
import java.security.*;

/**
 * JavaCrypt: An encryption program that uses RC4 and TEA.
 *
 * The algorithm is as follows:
 *   To encrypt:
 *		1. Create an encryption key (512 bits): CubeHash(password + #padded bits (see step 2) + random salt (128 bytes))
 *			-The salt prevents using rainbow tables
 *		2. Encrypt 64-bit chunks of data using 128-bit chunks of the key:
 *			-RC4, then TEA:
 *			 TEA(key, RC4(key, data))
 *		   If the chunk is the last one and has length < 64, pad it using random data
 *		3. Write data to the file as follows:
 *			/x01/x02/x03/x04/x05/x06	<- marker so I know the file is valid
 *			ABBBBBBBBBBBBBBBBB			<- A  = # of padded bits added to make 64-bit chunk at the end
 *										   B* = random salt (256 bits)
 *			xxxxxxxxxxxxxxxxxxx			<- x* = encrypted data
 *   *****************************************************************************************
 *   To decrypt:
 *		1. Check the starting marker to see if the file is valid
 *		2. Regenerate the encryption key: CubeHash(inputted password + 2nd line from file)
 *		3. Decrypt 64-bit chunks of data using 128-bit chunks of the key:
 *			-unTEA, then RC4 (RC4 is symmetric!):
 *			 RC4(key, unTEA(key, data))
 *		4. Delete the padding from the last 64-bit chunk only.
 *		5. Write the decrypted data back to the file.
 *
 * @author Stephen Solis
 * @version 03/22/2012
 */
public class JavaCrypt {
	/** This header is written by encrypt() and checked by decrypt() */
	private static final byte[] FILE_HEADER = {0x01, 0x02, 0x03, 0x04};

	private static String inFilename;
	private static String outFilename;
	private static byte[] password;

	public static void main(String[] args) throws IOException {
		boolean doEncrypt = getUserChoice();
		getFilenameAndPassword();

		if (doEncrypt)
			encrypt();
		else
			decrypt();
	}

	/**
	 * Asks the user whether they wish to encrypt or decrypt a file.
	 * @return true if the user wishes to encrypt, false if the user wishes to decrypt
	 */
	public static boolean getUserChoice() throws IOException{
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

		while (true){
			//print the message
			System.out.println();
			System.out.println("Make a choice:");
			System.out.println("1. Encrypt a file.");
			System.out.println("2. Decrypt a file.");
			System.out.println("3. Quit.");
			System.out.print("[1/2/3]: ");

			//perform the action the user requests
			try {
				int userChoice = Integer.parseInt(in.readLine());
				if (userChoice  == 1) //user chooses "Encrypt a file."
					return true;
				else if (userChoice == 2) //user chooses "Decrypt a file."
					return false;
				else if (userChoice == 3) //user chooses "Quit."
					System.exit(0);
				else
					System.out.println("Invalid choice."); //catch invalid input
			} catch (NumberFormatException e){
				System.out.println("Invalid choice."); //invalid input here too
			}
		}
	}

	/**
	 * Sets the global {in,out}Filename and password variables for encrypt()
	 * and decrypt() to use.
	 */
	public static void getFilenameAndPassword() throws IOException{
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		Console console = System.console();

		boolean validFilename = false;
		String currInput; //holds the user's input before we check it

		//get the input filename
		System.out.println(); //make output look neat
		while (!validFilename){
			//print the message
			System.out.print("Enter input filename: ");

			//check if the file exists.
			currInput = in.readLine();
			File file = new File(currInput);
			if (!file.exists())
				//if file doesn't exist, say so
				System.out.println("Can't access the file.\n");
			else{
				//if it does, go on
				inFilename = currInput;
				validFilename = true;
			}
		}

		//do the same for the output filename
		validFilename = false;
		while (!validFilename){
			//print the message
			System.out.print("Enter output filename: ");

			//check if the file exists.
			currInput = in.readLine();
			File file = new File(currInput);
			if (file.exists())
				//if file exists, say so
				System.out.println("File already exists.\n");
			else{
				//otherwise, create the file and continue
				file.createNewFile();
				outFilename = currInput;
				validFilename = true;
			}
		}

		//get the password
		System.out.print("Enter password: ");
		char[] passwordChar = console.readPassword();

		//convert the password from chars to a bytestream (ie. ASCII to binary)
		password = new byte[passwordChar.length];
		for (int i = 0; i < passwordChar.length; i++){
			password[i] = (byte)passwordChar[i];
		}
	}

	/**
	 * Encrypts the file specified in inFilename and puts the result in the
	 * file specified by outFilename.
	 */
	public static void encrypt() throws IOException{
		BufferedInputStream in = new BufferedInputStream(new FileInputStream(inFilename));
		BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outFilename));

		SecureRandom randomGen = new SecureRandom(); //used for the salt and the padding
		byte[] key; //holds the encryption key

		//get the file length
		long fileLength = (new File(inFilename)).length();

		//write the file header marker
		out.write(FILE_HEADER);

		/* STAGE 1 - generate encryption key */
		//find the number of bytes we have to pad and write it to the file
		int numPad;
		if (fileLength % 8 == 0)
			numPad = 0;
		else
			numPad = (int)(8 - (fileLength % 8));
		out.write(numPad);
		//generate a 128-byte random salt and write it to the file
		byte[] salt = new byte[128];
		randomGen.nextBytes(salt);
		out.write(salt);
		//generate the message for CubeHash: (password + #padded bits + random salt)
		byte[] message = new byte[password.length + 1 + salt.length];
		System.arraycopy(password, 0, message, 0, password.length); //add the password
		message[password.length] = (byte)numPad; //add #padded bits
		System.arraycopy(salt, 0, message, password.length + 1, salt.length); //add random salt
		//finally, generate the encryption key
		key = CryptoLib.CubeHash.doCubeHash(message);

		/* STAGE 2 - apply encryption */
		int currPiece = 0;  //keeps track of which piece of the key is being used
		byte[] currData = new byte[8]; //holds the piece of data currently being encrypted

		//split the key into 4 pieces of 128 bits each
		byte[][] keyPieces = new byte[4][16];
		for (int i = 0; i < 4; i++){
			System.arraycopy(key, i*16, keyPieces[i], 0, 16);
		}

		//loop through the file (except the last block), 8 bytes at a time
		for (long i = 0; i < fileLength - 8; i += 8){
			//put a chunk of data in currData
			in.read(currData);

			//do TEA(key, RC4(key, data)), then write to file
			out.write(CryptoLib.TEA.doTEA(keyPieces[currPiece],
						CryptoLib.RC4.doRC4(keyPieces[currPiece], currData)));

			//increment currPiece
			currPiece = (currPiece + 1) % 4;
		}

		//deal with the last block of data:
		//first, read it..
		in.read(currData);
		//..pad it with random data..
		for (int i = 7; i >= (8 - numPad); i--){
			currData[i] = (byte)randomGen.nextInt();
		}
		//..then encrypt it
		out.write(CryptoLib.TEA.doTEA(keyPieces[currPiece],
					CryptoLib.RC4.doRC4(keyPieces[currPiece], currData)));

		/* STAGE 3 - done! */
		in.close();
		out.close();
		System.out.println("\nEncryption complete.");
	}

	/**
	 * Decrypts the file specified in inFilename and puts the result in the
	 * file specified by outFilename.
	 */
	public static void decrypt() throws IOException{
		BufferedInputStream in = new BufferedInputStream(new FileInputStream(inFilename));
		BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outFilename));

		byte[] key; //holds the encryption key

		//get the file length
		long fileLength = (new File(inFilename)).length();

		//check the file header marker
		byte[] actualHeader = new byte[FILE_HEADER.length];
		in.read(actualHeader); //read header from the file
		if (!Arrays.equals(actualHeader, FILE_HEADER)){
			System.out.println("The file was not encrypted with this program.");
			System.exit(-1); //-1 is an error code
		}

		/* STAGE 1 - generate decryption key */
		//read the #padded bits and random salt from the file
		byte[] dataFromFile = new byte[129]; //1 byte for #padded bits + 128 bytes for salt
		in.read(dataFromFile);
		//separate the #padded bits for use later
		int numPad = (int)(dataFromFile[0]);
		//next, generate the message for CubeHash: (password + dataFromFile)
		byte[] message = new byte[password.length + dataFromFile.length];
		System.arraycopy(password, 0, message, 0, password.length); //add the password
		System.arraycopy(dataFromFile, 0, message, password.length, dataFromFile.length); //add dataFromFile
		//finally, (re)generate the encryption key
		key = CryptoLib.CubeHash.doCubeHash(message);

		/* STAGE 2 - apply decryption */
		int currPiece = 0; //keeps track of which piece of the key is being used
		byte[] currData = new byte[8]; //holds the data currently being decrypted

		//split the key into 4 pieces of 128 bits each
		byte[][] keyPieces = new byte[4][16];
		for (int i = 0; i < 4; i++){
			System.arraycopy(key, i*16, keyPieces[i], 0, 16);
		}

		//loop through the rest of the file (except the last block), 8 bytes at a time
		for (long i = FILE_HEADER.length + 129; i < fileLength - 8; i += 8){
			//put a chunk of data in currData
			in.read(currData);

			//do RC4(key, unTEA(key, data)), then write to file
			out.write(CryptoLib.RC4.doRC4(keyPieces[currPiece],
						CryptoLib.TEA.doUnTEA(keyPieces[currPiece], currData)));

			//increment currPiece
			currPiece = (currPiece + 1) % 4;
		}

		//deal with the last chunk of data:
		//first, read it..
		in.read(currData);
		//..decrypt it..
		currData = CryptoLib.RC4.doRC4(keyPieces[currPiece],
				CryptoLib.TEA.doUnTEA(keyPieces[currPiece], currData));
		//..then write it to the file
		out.write(currData, 0, (8 - numPad));

		/* STAGE 3 - done!  */
		in.close();
		out.close();
		System.out.println("\nDecryption complete.");
	}
}
