import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.DataInputStream;
import java.security.cert.CertificateFactory;
import javax.security.auth.DestroyFailedException;
import javax.crypto.NoSuchPaddingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;

public class Vault {
    private static final int MAX_MESSAGE_SIZE = 1_000_000;
    private static final int ENCODED_KEY_SIZE = 344; // size of key after encryption, counted characters after key was made
    private static final String ROOT_CERT_NAME = "root_X0F.crt";
    private static final String PRIVATE_KEY_NAME = "matt.priv";
    private static String user;

    // NOTE: If youre IDE does not support the use of the Console class, you can
    // debug with a scanner.   You would want to test your program, though, once
    // you are done with the other testing, using the Console class.
    private static boolean IDE_DEBUG = false;
    private static Console console;

    static {
        console = System.console();
        if (console == null) {
            System.err.println("No console available!");
            System.exit(-1);
        }
    }

    public static void main(String[] args) {
        if (!authenticate()) {
            System.out.println("Invalid username or password");
            System.exit(-1);
        }

        int choice = 0;
        while (choice != 7) {
            choice = displayMenu();
            switch (choice) {
                case 1:
                    displayFile();
                    break;
                case 2:
                    replaceFile();
                    break;
                case 3:
                    changePassword(true);
                    break;
                case 4:
                    enrollNewUser();
                    break;
                case 5:
                    exportFile();
                    break;
                case 6:
                    importFile();
                    break;
            }
        }
    }

    private static void displayFile() {
        try (Scanner vault = new Scanner(new File("vault.txt"))) {
            while (vault.hasNextLine()) {
                System.out.println(vault.nextLine());
            }
        } catch (FileNotFoundException e) {
            return;
        }
    }

    /**
     * Display the menu for the user.
     * v2 change log
     * - we are using the console to get user input, instead of a scanner.
     *
     * @return the user's choice
     */
    private static int displayMenu() {
        System.out.println("1) Display file");
        System.out.println("2) Replace file");
        System.out.println("3) Change password");
        System.out.println("4) Add user");
        System.out.println("5) Export file");
        System.out.println("6) Import file");
        System.out.println("7) Quit");
        System.out.print("\nEnter your choice (1-7): ");
        return Integer.valueOf(console.readLine());
    }

    /**
     * OPTION 2
     * <p>
     * Replace the contents of the vault file.
     * v2 change log
     * - The input from the user is obtained via the Console object.
     * - We gather the input in a char buffer, which is then cleared.
     */
    private static void replaceFile() {
        System.out.println("Enter your message.  When you are done type enter by itself on a blank line");
        char[] message = new char[MAX_MESSAGE_SIZE];
        int size = 0;
        String line = console.readLine();
        try {
            while (!line.equals("")) {
                for (int i = 0; i < line.length(); i++) {
                    message[size++] = line.charAt(i);
                }
                message[size++] = '\n';
                line = console.readLine();
            }
        } catch (IndexOutOfBoundsException e) {
            clearArray(message);
            System.out.println("The vault input exceeded the maximum vault size.");
            System.exit(-1);
        }

        try (PrintWriter vault = new PrintWriter(new File("vault.txt"))) {
            // NOTE: You should be careful to avoid a call to:
            // vault.print(message);
            // This will translate the CharBuffer to a String, which is something we want to avoid.
            for (int i = 0; i < size; i++) {
                vault.print(message[i]);
                message[i] = ' ';
            }
        } catch (FileNotFoundException e) {
            clearArray(message);
            System.out.println("Unable to update the vault." + e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * OPTION 3
     * <p>
     * Allow the user to change their password.
     * v2 change log
     * - We are now using a char array to store the typed password, and removing it
     * from memory when we are done.
     * - If the user has just authenticated, the parameter authenticationRequired can
     * be set to false, so that they do not need to authenticate twice.
     *
     * @param authenticationRequired do we require authentication to change the password
     */
    private static void changePassword(boolean authenticationRequired) {
        if (!authenticationRequired || authenticate()) {
            char[] password = enterNewPassword();

            ArrayList<String> entries = new ArrayList<>();
            try (Scanner scUsers = new Scanner(new File("users.txt"))) {
                while (scUsers.hasNextLine()) {
                    String line = scUsers.nextLine();
                    String[] tokens = line.split(":");
                    if (!tokens[0].equals(user)) {
                        entries.add(line);
                    }
                }
            } catch (FileNotFoundException e) {
                clearArray(password);
                System.out.println("Unable to update the password.");
                System.exit(-1);
            }

            try (PrintWriter pwUsers = new PrintWriter(new File("users.txt"))) {
                for (String entry : entries) {
                    pwUsers.println(entry);
                }
                pwUsers.print(user);
                pwUsers.print(":");
                for (int i = 0; i < password.length; i++) {
                    pwUsers.print(password[i]);
                }
                clearArray(password);
                pwUsers.println(":F");
            } catch (FileNotFoundException e) {
                clearArray(password);
                System.out.println("Unable to update the password.");
                System.exit(-1);
            }
        }
    }

    /**
     * OPTION 4
     * <p>
     * Enroll a new user.
     * v2 change log
     * - We use the new password routine to prompt the user for a password in
     * a more secure fashion.
     * - The contents of the memory containing this password are cleared when
     * it is no longer needed.
     * - We set a flag requiring the new user to change their password upon their
     * next login.
     */
    private static void enrollNewUser() {
        System.out.print("Enter a new username: ");
        String user = console.readLine();
        char[] password = enterNewPassword();

        boolean ok = true;
        ArrayList<String> entries = new ArrayList<>();
        try (Scanner scUsers = new Scanner(new File("users.txt"))) {
            while (ok && scUsers.hasNextLine()) {
                String line = scUsers.nextLine();
                String[] tokens = line.split(":");
                if (tokens[0].equals(user)) {
                    ok = false;
                } else {
                    entries.add(line);
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("Unable to update the users list.");
            ok = false;
        }

        if (ok) {
            try (PrintWriter pwUsers = new PrintWriter(new File("users.txt"))) {
                for (String entry : entries) {
                    pwUsers.println(entry);
                }
                pwUsers.print(user + ":");
                for (int i = 0; i < password.length; i++) {
                    pwUsers.print(password[i]);
                }
                pwUsers.println(":T");
            } catch (FileNotFoundException e) {
                System.out.println("Error updating the users list.");
                System.exit(-1);
            }
        }
        clearArray(password);
    }

    /**
     * OPTION 5
     * <p>
     * Export the contents of the vault file to an encrypted share.txt file.
     * <p>
     * v2 change log
     * - We create a symmetric key to encrypt the contents of the vault.  This key is base-64 encoded and
     * written to key.txt
     * - We write the initialization vector and the base-64 encoded, encrypted message to vault.txt
     */
    private static void exportFile() {
        System.out.println("Please type in your email address: ");
        String emailAcc = console.readLine();
        System.out.println("Please type in your certificate file name: ");
        String certFileName = console.readLine();
        boolean result = checkCerts(emailAcc, certFileName);
        if (!result) {
            //checkCerts displays necessary error message
            return;
        }
        // Initialize the crypto system
        SecretKey aesKey = null;
        Cipher cipher = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Collection<X509Certificate> certs = (Collection<X509Certificate>)
                    certFactory.generateCertificates(new FileInputStream(certFileName));
            X509Certificate receiverCert = certs.iterator().next();
            aesKey = KeyGenerator.getInstance("AES").generateKey();
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.WRAP_MODE, receiverCert.getPublicKey());
            String wrappedKey = Base64.getEncoder().encodeToString(rsaCipher.wrap(aesKey));
            try (PrintWriter key = new PrintWriter(new File("key.txt"))) {
                key.println(wrappedKey);
            }
        }
        // Note: Avoid Pokemon Exception Handling.  Think about all exceptions that could
        // occur and make sure that you are handling them appropriately.
        // Also be sure not to reveal anything about the way that the encryption is being
        // performed in the error messages.
        catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | IllegalBlockSizeException e) {
            System.out.println("Error with the configuration of the Java Virtual Machine.");
            System.exit(-1);
        } catch (CertificateException e) {
            System.out.println("Input is invalid");
            return;
        } catch (FileNotFoundException e) {
            System.out.println("Unable to export the file.");
            return;
        }

        try {
            aesKey.destroy();
        } catch (DestroyFailedException e) {
            // Not all implementations have this method defined.
        }

        // Read the vault
        char[] message = new char[MAX_MESSAGE_SIZE];
        int size = 0;
        try (Scanner vault = new Scanner(new File("vault.txt"))) {
            if (vault != null) {
                while (vault.hasNextLine()) {
                    String line = vault.nextLine();
                    for (int i = 0; i < line.length(); i++) {
                        message[size++] = line.charAt(i);
                    }
                    message[size++] = '\n';
                }
            }
        } catch (IndexOutOfBoundsException e) {
            clearArray(message);
            System.out.println("The vault file has exceeded the maximum size.  Unable to export");
            return;
        } catch (FileNotFoundException e) {
            // Continue with a blank message to be decoded.
        }

        // Get encoded ciphertext
        byte[] plaintext = toByteArray(message, size);
        clearArray(message);
        String encodedCipherText = null;
        try {
            encodedCipherText = Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            // Note that these exceptions should only occur when decrypting
            clearArray(plaintext);
            System.out.println("Error with the configuration of the Java Virtual Machine.");
            System.exit(-1);
        }
        clearArray(plaintext);

        // Write ciphertext to file
        try (PrintWriter share = new PrintWriter(new File("share.txt"))) {
            // Write IV
            // Note: To test ECB, comment out next line
            share.println(Base64.getEncoder().encodeToString(cipher.getIV()));

            // Write ciphertext
            share.println(encodedCipherText);
        } catch (FileNotFoundException e) {
            System.out.println("Unable to update the shared file.");
            System.exit(-1);
        }
    }

    /**
     * Import the share.txt file
     * v2 change log
     * - the file now contains encrypted ciphertext
     *
     * @throws
     */
    private static void importFile() {
        // Initialize the crypto system
        // Get the key
        byte[] encryptedPrivKeyBytes = new byte[ENCODED_KEY_SIZE];
        SecretKey unwrappedKey = null;
        File privKeyFile = new File(PRIVATE_KEY_NAME);
        try (DataInputStream dis = new DataInputStream(new FileInputStream(privKeyFile))){
            encryptedPrivKeyBytes = new byte[(int) privKeyFile.length()];
            dis.read(encryptedPrivKeyBytes);
            dis.close();
        } catch (IOException e){
            System.out.println("Critical validation error");
        }
        EncryptedPrivateKeyInfo encryptPrivKeyInfo = null;
        try {
            encryptPrivKeyInfo= new EncryptedPrivateKeyInfo(encryptedPrivKeyBytes);
        } catch (IOException e){
            System.out.println("Critical validation error");
        }
        // Prompt user for encryption password.
        // Collect user password as char array (using the
        // "readPassword" method from above)
        System.out.println("Type in your password");
        char[] passData = console.readPassword();
        // Convert the password to a secret key, using a PBE key factory.
        // This is the same secret key that was used to encrypt the key in
        // the PKCS 8 file
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passData);
        Arrays.fill(passData, ' '); // Clear data in password array so that it does
        // not stay in memory
        try (InputStream keyFile = new FileInputStream(new File("key.txt"))){
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance(encryptPrivKeyInfo.getAlgName());
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
            pbeKeySpec.clearPassword();

            Cipher cipher = Cipher.getInstance(encryptPrivKeyInfo.getAlgName());
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, encryptPrivKeyInfo.getAlgParameters());
            PrivateKey privKey = KeyFactory.getInstance("RSA").generatePrivate(encryptPrivKeyInfo.getKeySpec(cipher));
            Cipher rsaCipher2 = Cipher.getInstance("RSA");
            rsaCipher2.init(Cipher.UNWRAP_MODE, privKey);
            byte[] bSecret = new byte[ENCODED_KEY_SIZE];
            int i = 0;
            int b = keyFile.read();
            while (b != '\n' && b != '\r') {
                bSecret[i++] = (byte) b;
                b = keyFile.read();
            }
            unwrappedKey = (SecretKey) rsaCipher2.unwrap(
                    Base64.getDecoder().decode(bSecret),
                    "AES", Cipher.SECRET_KEY);
        }
        catch (IOException e) {
            System.out.println("Unable to update the vault.");
            System.exit(-1);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | NullPointerException
                | InvalidAlgorithmParameterException e){
            System.out.println("Critical validation error");
        } catch (InvalidKeyException
                | InvalidKeySpecException e) {
            System.out.println("Incorrect password");
        }
        // Read the share.txt file
        byte[] iv = null;
        byte[] ciphertext = null;
        try (Scanner share = new Scanner(new File("share.txt"))){
            // Note to test ECB, comment out next line
            iv = Base64.getDecoder().decode(share.nextLine());
            ciphertext = Base64.getDecoder().decode(share.nextLine());
        } catch (FileNotFoundException e) {
            System.out.println("share.txt File cannot be found");
            return;
        }

        // Initialize the cipher
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, unwrappedKey, new IvParameterSpec(iv));
        }
        catch(NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException e) {
            System.out.println("Error with the configuration of the Java Virtual Machine.");
            System.exit(-1);
        }

        try {
            unwrappedKey.destroy();
        } catch (DestroyFailedException e) {
            // destroy may not be implemented
        }
        byte[] plaintext = null;
        try {
            plaintext = cipher.doFinal(ciphertext);
        } catch (IllegalBlockSizeException
                | BadPaddingException e1) {
            clearArray(plaintext);
            System.out.println("Error importing file.");
            System.exit(-1);
        }

        if (plaintext.length > MAX_MESSAGE_SIZE) {
            System.out.println("Import file exceeded max vault size.");
            System.exit(-1);
        }

        try (PrintWriter vault = new PrintWriter(new File("vault.txt"))){
            for (int i = 0; i < plaintext.length; i++) {
                vault.print((char) plaintext[i]);
                plaintext[i] = ' ';
            }
        } catch (FileNotFoundException
                | NullPointerException e) {
            System.out.println("Unable to write to the vault file.");
        }
    }

    /**
     * Authenticate the user.
     * v2 change log
     * - We are using the console to mask the characters that the user types.
     * - We are ensuring that the password that is typed in is removed from memory when it is no
     * longer needed.
     * - We prompt the user to change their password if they successfully authenticate, and the change
     * password flag is set
     *
     * @return whether the user was authenticated
     */
    private static boolean authenticate() {
        System.out.print("Enter your username: ");
        user = console.readLine();
        char[] password = console.readPassword("Enter your password: ");

        boolean result = false;
        try (Scanner users = new Scanner(new File("users.txt"))) {
            while (!result && users.hasNextLine()) {
                String[] tokens = users.nextLine().split(":");
                if (tokens.length == 3 && tokens[0].equals(user) &&
                        Arrays.equals(tokens[1].toCharArray(), password)) {

                    if (tokens[2].equals("T")) {
                        System.out.println("You are required to change your password the first time you log in.");
                        changePassword(false);
                    }

                    result = true;
                }
            }
        } catch (Exception e) {
            System.err.println("An error occurred during authentication");
            System.exit(-1);
        }
        clearArray(password);
        return result;
    }

    /**
     * Prompt the user to enter a new password.  The password will be
     * entered twice, and we will ensure that the passwords match.  We
     * also ensure that the password does not contain a ':' character
     *
     * @return the new password
     */
    private static char[] enterNewPassword() {
        char[] password1 = null;
        boolean ok = false;
        while (!ok) {
            password1 = console.readPassword("Enter a new password: ");

            ok = true;
            for (int i = 0; !ok && i < password1.length; i++) {
                if (password1[i] == ':') {
                    System.out.println("The password cannot contain a colon (:).");
                    ok = false;
                }
            }
            if (ok) {
                char[] password2 = console.readPassword("Renter a new password: ");
                if (!Arrays.equals(password1, password2)) {
                    System.out.println("The passwords do not match.");
                    ok = false;
                }
                clearArray(password2);
            }
            if (!ok) {
                clearArray(password1);
            }
        }
        return password1;
    }

    /**
     * Clear the contents of the array
     *
     * @param array An array containing sensitive information
     */
    private static void clearArray(char[] array) {
        if (array == null) return;
        for (int i = 0; i < array.length; i++) {
            array[i] = 0;
        }
    }

    /**
     * Clear the contents of a byte array
     *
     * @param array An array containing sensitive information
     */
    private static void clearArray(byte[] array) {
        if (array == null) return;
        for (int i = 0; i < array.length; i++) {
            array[i] = 0;
        }
    }

    /**
     * Convert a CharBuffer to a byte array
     *
     * @param array The CharBuffer with contents to be converted
     */
    private static byte[] toByteArray(char[] array, int size) {
        byte[] retArray = new byte[size];
        for (int i = 0; i < size; i++) {
            retArray[i] = (byte) array[i];
        }
        return retArray;
    }

    private static boolean checkCerts(String subject, String fileName) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            // Grab the (possible chain of) certificates from the file
            // The main certificate is the first one in the collection
            Collection<X509Certificate> certs1 = (Collection<X509Certificate>)
                    certFactory.generateCertificates(new FileInputStream(fileName));
            Collection<X509Certificate> certs2 = (Collection<X509Certificate>)
                    certFactory.generateCertificates(new FileInputStream(ROOT_CERT_NAME));

            X509Certificate receiverCert = certs1.iterator().next();
            X509Certificate CACert = certs2.iterator().next();

            if ((CACert.getBasicConstraints() != -1)
                    && (receiverCert.getSubjectX500Principal().toString().contains(subject))
                    && (receiverCert.getIssuerDN().equals(CACert.getIssuerDN()))) {  //checks issuer
                // verify signature
                receiverCert.verify(CACert.getPublicKey());
                CACert.verify(CACert.getPublicKey());

                // Check period of validity
                receiverCert.checkValidity();
                CACert.checkValidity();
                return true;
            } else {
                System.out.println("Unsuccessful certificate verification");
                return false;
            }
        } catch (CertificateException
                | FileNotFoundException
                | InvalidKeyException
                | SignatureException e) {
            System.out.println("Credentials are not valid");
            return false;
        } catch (NoSuchAlgorithmException
                | NullPointerException
                | NoSuchProviderException e) {
            System.out.println("Critical validation error");
            return false;
        }
    }
}
