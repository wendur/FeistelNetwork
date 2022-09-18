import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;


public class Main {
    public static void main(String[] args) throws IOException {
        FileInputStream messageFile = new FileInputStream("Source/Message.txt");
        byte[] byteMessage = messageFile.readAllBytes();
        messageFile.close();

        FileInputStream passwordFile = new FileInputStream("Source/Password.txt");
        byte[] bytePassword = passwordFile.readAllBytes();
        passwordFile.close();
        ///System.out.println(Arrays.toString(bytePassword) + " " + bytesToLong(bytePassword));

        System.out.println("Password - " + new String(bytePassword));
        System.out.println("Message: \n" + new String(byteMessage));

        ///System.out.println(Arrays.toString(byteMessage) + " " + Arrays.toString(bytesToLongs(byteMessage)));
        Random random = new Random();
        long longInitVector = random.nextLong();

        byte[] byteEncryptMessage = encryptionFunction(byteMessage, bytePassword);
        System.out.println("Encrypted message: \n" + new String(byteEncryptMessage));

        byte[] byteEncryptMessageCBC = encryptionFunctionCBC(byteMessage, bytePassword, longInitVector);
        System.out.println("Encrypted message(CBC): \n" + new String(byteEncryptMessageCBC));

        byte[] byteDecryptMessage = decryptionFunction(byteEncryptMessage, bytePassword);
        System.out.println("Decrypted message: \n" + new String(byteDecryptMessage));

        byte[] byteDecryptMessageCBC = decryptionFunctionCBC(byteEncryptMessageCBC, bytePassword, longInitVector);
        System.out.println("Decrypted message(CBC): \n" + new String(byteDecryptMessageCBC));
    }

    public static byte[] encryptionFunction(byte[] byteMessage, byte[] key) {
        long[] longBlocksMessage = bytesToLongs(byteMessage);
        long[] encryptedBlocks = new long[longBlocksMessage.length];
        for (int i = 0; i < encryptedBlocks.length; i++) {
            encryptedBlocks[i] = encrypt(longBlocksMessage[i], bytesToLong(key));
        }
        return longsToBytes(encryptedBlocks);
    }

    public static byte[] encryptionFunctionCBC(byte[] byteMessage, byte[] key, long initVector) {
        long[] longBlocksMessage = bytesToLongs(byteMessage);
        long[] encryptedBlocks = new long[longBlocksMessage.length];
        encryptedBlocks[0] = encrypt(longBlocksMessage[0] ^ initVector, bytesToLong(key));
        for (int i = 1; i < encryptedBlocks.length; i++) {
            encryptedBlocks[i] = encrypt(longBlocksMessage[i] ^ encryptedBlocks[i-1], bytesToLong(key));
        }
        return longsToBytes(encryptedBlocks);
    }

    public static long encrypt(long message, long key) {
        short[] blocks = messageToBlocks(message);
        short[] tempBlocks = Arrays.copyOf(blocks, blocks.length);
        int rounds = 10;
        short[] roundKeys = keyGenerator(key, rounds);
        for (int i = 0; i < rounds; i++) {
            tempBlocks[2] = (short) (blocks[3] ^ roundKeys[i]);
            tempBlocks[1] = (short) (blocks[2] ^ tempBlocks[2]);
            tempBlocks[0] = blocks[1];
            tempBlocks[3] = (short) (blocks[0] ^ function(tempBlocks[0], tempBlocks[1], tempBlocks[2]));
            blocks = Arrays.copyOf(tempBlocks, tempBlocks.length);
        }
        return shortBlocksToLong(blocks);
    }

    public static byte[] decryptionFunction(byte[] byteEncryptedMessage, byte[] key) {
        long[] longBlocksMessage = bytesToLongs(byteEncryptedMessage);
        long[] decryptedBlocks = new long[longBlocksMessage.length];
        for (int i = 0; i < decryptedBlocks.length; i++) {
            decryptedBlocks[i] = decrypt(longBlocksMessage[i], bytesToLong(key));
        }
        return longsToBytes(decryptedBlocks);
    }

    public static byte[] decryptionFunctionCBC(byte[] byteEncryptedMessage, byte[] key, long initVector) {
        long[] longBlocksMessage = bytesToLongs(byteEncryptedMessage);
        long[] decryptedBlocks = new long[longBlocksMessage.length];
        decryptedBlocks[0] = decrypt(longBlocksMessage[0], bytesToLong(key)) ^ initVector;
        for (int i = 1; i < decryptedBlocks.length; i++) {
            decryptedBlocks[i] = decrypt(longBlocksMessage[i], bytesToLong(key)) ^ longBlocksMessage[i-1];
        }
        return longsToBytes(decryptedBlocks);
    }

    public static long decrypt(long message, long key) {
        short[] blocks = messageToBlocks(message);
        short[] tempBlocks = Arrays.copyOf(blocks, blocks.length);
        int rounds = 10;
        short[] roundKeys = keyGenerator(key, rounds);
        for (int i = 0; i < rounds; i++) {
            tempBlocks[0] = (short) (blocks[3] ^ function(blocks[0], blocks[1], blocks[2]));
            tempBlocks[1] = blocks[0];
            tempBlocks[2] = (short) (blocks[1] ^ blocks[2]);
            tempBlocks[3] = (short) (blocks[2] ^ roundKeys[rounds - i - 1]);
            blocks = Arrays.copyOf(tempBlocks, tempBlocks.length);
        }
        return shortBlocksToLong(blocks);
    }

    public static short function(short block0, short block1, short block2) {
        return (short) (~block0 ^ cyclingShiftRight(block1, 5) ^ cyclingShiftLeft(block2, 7));
    }

    public static short[] keyGenerator(long key, int rounds) {
        short[] keys = new short[rounds];
        for (int i = 0; i < rounds; i++) {
            keys[i] = (short) (key >>> rounds * i ^ key);
        }
        return keys;
    }

    public static long cyclingShiftRight(short block, int i) {
        return (long) (block >>> i | (long) block << Long.toBinaryString(block).length() - i);
    }

    public static long cyclingShiftLeft(short block, int i) {
        return (long) ((long) block << i | block >>> Long.toBinaryString(block).length() - i);
    }

    public static byte[] longsToBytes(long[] longs) {
        List<Byte> byteList = new ArrayList<>();
        for (long l : longs) {
            byteList.add(((byte) (l >>> 56)));
            byteList.add(((byte) (l >>> 48)));
            byteList.add(((byte) (l >>> 40)));
            byteList.add(((byte) (l >>> 32)));
            byteList.add(((byte) (l >>> 24)));
            byteList.add(((byte) (l >>> 16)));
            byteList.add(((byte) (l >>> 8)));
            byteList.add(((byte) l));
        }
        byte[] byteArray = new byte[byteList.size()];
        for (int i = 0; i < byteArray.length; i++) {
            byteArray[i] = byteList.get(i);
        }
        return byteArray;
    }

    public static long[] bytesToLongs(byte[] bytes) {
        ///System.out.println((int) Math.ceil((float) bytes.length / 8));
        long[] longs = new long[(int) Math.ceil((float) bytes.length / 8)];
        byte[] number = new byte[8];
        for (int i = 0; i < longs.length - 1; i++) {
            for (int j = i * 8; j < (i + 1) * 8; j++) {
                number[j % 8] = bytes[j];
            }
            longs[i] = bytesToLong(number);
        }
        byte[] endNumber = new byte[8];
        for (int i = 0; i < 8; i++) {
            if ((longs.length - 1) * 8 + i < bytes.length){
                endNumber[i] = bytes[(longs.length - 1) * 8 + i];
            } else {
                endNumber[i] = 32;
            }
        }
        longs[longs.length-1] = bytesToLong(endNumber);
        return longs;
    }

    public static long bytesToLong(byte[] bytes) {
        long number = 0;
        for (byte b : bytes) {
            number <<= 8;
            number |= (b & 0xff);
        }
        return number;
    }

    private static long shortBlocksToLong(short[] blocks) {
        long number = 0L;
        for (short b : blocks) {
            number = (number << 16) + (b & 0xffff);
        }
        return number;
    }

    public static short[] messageToBlocks(long message) {
        short[] blocks = new short[4];
        for (int i = 0; i < 4; i++) {
            blocks[i] = (short) (message >>> (3 - i) * 16);
        }
        return blocks;
    }
}