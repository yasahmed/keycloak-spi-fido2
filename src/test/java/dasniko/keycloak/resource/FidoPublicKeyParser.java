package dasniko.keycloak.resource;

import com.upokecenter.cbor.CBORObject;

import java.util.Base64;

public class FidoPublicKeyParser {
    public static void main(String[] args) {
        // Base64 encoded FIDO public key
        String b64FidoKey = "pQECAyYgASFYIC5kX1xUuGWqZjSRA-Ap3ElWHEEEekqgc2JSlutiAisnIlggakwsYu6fv-uLf59Aqv5gc9Sk0w4ZHu_7R26-PUaGdyg";

        // Step 1: Base64 Decode
        byte[] binaryKey = Base64.getUrlDecoder().decode(b64FidoKey);

        // Step 2: CBOR Decode
        CBORObject decodedKey = CBORObject.DecodeFromBytes(binaryKey);

        // Print the decoded key to inspect its structure
        System.out.println(decodedKey.toString());

        // Try printing each key to see what is actually there
        for (CBORObject key : decodedKey.getKeys()) {
            System.out.println("Key: " + key + ", Value: " + decodedKey.get(key));
        }

        // Extracting the actual key information
        // Assuming the structure is similar to the previous assumption
        // and adjusting based on the printed structure

        CBORObject keyTypeObject = decodedKey.get(CBORObject.FromObject(1)); // Example key representation
        CBORObject algorithmObject = decodedKey.get(CBORObject.FromObject(3)); // Example key representation

        // Since "x" and "y" are not present, we will identify their actual keys based on the printed structure
        CBORObject xCoordObject = null; // Update this after inspecting the printed structure
        CBORObject yCoordObject = null; // Update this after inspecting the printed structure

        // Check if the keys are present
        if (keyTypeObject == null || algorithmObject == null) {
            System.err.println("Error: One or more keys are not present in the decoded CBOR object.");
            return;
        }

        if (xCoordObject == null || yCoordObject == null) {
            System.err.println("Error: X or Y coordinates are not present in the decoded CBOR object.");
            return;
        }

        // Step 3: Extract the Key Information
        int keyType = keyTypeObject.AsInt32();
        int algorithm = algorithmObject.AsInt32();
        byte[] xCoord = xCoordObject.GetByteString();
        byte[] yCoord = yCoordObject.GetByteString();

        // Print the extracted key information
        System.out.println("Key Type: " + keyType);
        System.out.println("Algorithm: " + algorithm);
        System.out.println("X Coordinate: " + bytesToHex(xCoord));
        System.out.println("Y Coordinate: " + bytesToHex(yCoord));
    }

    // Helper method to convert byte array to hex string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
