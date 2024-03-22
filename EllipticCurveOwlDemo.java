/* 
 * @author: Feng Hao, haofeng66@gmail.com
 * 
 * This Java demo program shows an elliptic curve implementation of the Owl protocol. 
 * Owl is obtained by efficiently adapting J-PAKE to an augmented setting.
 * 
 * This program is adapted from an elliptic curve implementation of J-PAKE
 * https://www.dcs.warwick.ac.uk/~fenghao/files/EllipticCurveJPAKEDemo.java 
 * 
 * Paper: Feng Hao, Samiran Bag, Liqun Chen, Paul van Oorschot, "Owl: 
 * An Augmented Password-Authenticated Key Exchange Scheme," FC, 2024
 * https://eprint.iacr.org/2023/768.pdf

 * License: MIT license
 *
 * Dependence: BouncyCastle library (https://www.bouncycastle.org/java.html) 
 *  
 * Acknowledgement: I thank Henry Lunn and Christopher Newton for kindly reviewing the code
 * 
 * Date: 22 March, 2024.
 *  
 */

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class EllipticCurveOwlDemo {

	/*
	 * See [1] for public domain parameters for NIST standard curves
	 * P-224, P-256, P-384, P-521. This demo code only uses P-256 as an example. One can also
	 * use other curves that are suitable for Elliptic Curve Cryptography, e.g., Curve25519.
	 *  
	 * [1] D. Johnson, A. Menezes, S. Vanstone, "The Elliptic Curve Digital Signature Algorithm (ECDSA)",
	 *     International Journal of Information Security, 2001. Available at
	 *     https://link.springer.com/article/10.1007/s102070100002
	 */
	
	private ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");

	/*
	 * Domain parameters
	 * We try to follow the same symbols used in the academic literature. This means that
	 * in some cases, we may break the Java naming convention and use a variable name that 
	 * starts with a capital letter.
	 */
	private ECCurve.Fp ecCurve = (ECCurve.Fp)ecSpec.getCurve();	
	private BigInteger a = ecCurve.getA().toBigInteger();
	private BigInteger b = ecCurve.getB().toBigInteger();
	private BigInteger q = ecCurve.getQ();
	private BigInteger coFactor = ecSpec.getH(); // Not using the symbol "h" here to avoid confusion as h will be used later in SchnorrZKP. 
	private BigInteger n = ecSpec.getN();
	private ECPoint G = ecSpec.getG();
	
	// Identities for the client and the server
	private String userName = "Alice";
	private String serverName = "Server"; 

	// Passwords. Change them to different values to simulate a failed login
	private String passwordRegister = "deadbeef"; // password used in registration
	private String passwordLogin = "deadbeef"; // password used in login
	
    public static void main(String args[]) {

    		EllipticCurveOwlDemo test = new EllipticCurveOwlDemo();
    		test.run();
    }

    private void run () {
	
    		System.out.println("************ Public elliptic curve domain parameters ************\n");
    		System.out.println("Curve param a (" + a.bitLength() + " bits): "+ a.toString(16));
    		System.out.println("Curve param b (" + b.bitLength() + " bits): "+ b.toString(16));    	    	
    		System.out.println("Co-factor h (" + coFactor.bitLength() + " bits): " + coFactor.toString(16));
    		System.out.println("Base point G (" + G.getEncoded(true).length + " bytes): " + pointToHex(G));
    		System.out.println("X coord of G (" + G.normalize().getXCoord().toBigInteger().bitLength() + " bits): " + G.getXCoord().toBigInteger().toString(16));
    		System.out.println("y coord of G (" + G.normalize().getYCoord().toBigInteger().bitLength() + " bits): " + G.getYCoord().toBigInteger().toString(16));
    		System.out.println("Order of the base point n (" + n.bitLength() + " bits): "+ n.toString(16));
    		System.out.println("Prime field q (" + q.bitLength() + " bits): "+ q.toString(16));
    		
    		System.out.println("\nUser name: " + userName);
    		System.out.println("Server name: " + serverName);
    		System.out.println("Password used in registration: " + passwordRegister);
    		System.out.println("Password used in login: " + passwordLogin);

    		
    		System.out.println("");
    		System.out.println("************ Registration ************\n");
    	
    		// t = H(username || password) mod n
    		BigInteger t = getSHA256(userName, passwordRegister).mod(n);

    		// pi = H(t) mod n
    		BigInteger pi = getSHA256(t).mod(n);
    	
    		// T = t x G
    		ECPoint T = G.multiply(t);
    	
    		// A secure channel is required for registration, but not for login.
    		System.out.println("Client sends to Server (over a secure channel)");
    		System.out.println("username: " + userName); 
    		System.out.println("pi: " + pi.toString(16)); 
    		System.out.println("T: " + pointToHex(T));
    	
    		/*
    		 *  Server computes X3 = x3 * G and zkpx3
    		 *  Owl defines x3 in [0, q-1] in the MODP setting, but x3=0 is naturally excluded
    		 *  in the EC setting. Hence we choose x3 from [1, n-1]. 
    		 */
    		BigInteger x3 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	
    		ECPoint X3 = G.multiply(x3);
    		SchnorrZKP zkpX3 = new SchnorrZKP();
    		zkpX3.generateZKP(G, n, x3, X3, serverName);
    	
    		System.out.println("\nServer generates the following to complete the client registration");
    		System.out.println("G*x3: "+pointToHex(X3));
    		System.out.println("KP{x3}: {V="+pointToHex(zkpX3.getV())+"; r="+zkpX3.getr().toString(16)+"}");

    		System.out.println("\n************ Login ************\n");
    
    		// t = H(username || password) mod n
    		BigInteger tLogin = getSHA256(userName, passwordLogin).mod(n);

    		// pi = H(t) mod n
    		BigInteger piLogin = getSHA256(tLogin).mod(n);
    	
    		/* First pass:  
    		 * 
    		 * Client chooses x1 randomly from [1, n-1], x2 from [1, n-1]
    		 * Client -> Server: G*x1, G*x2 and ZKP{x1}, ZKP{X2}
    		 * 
    		 * Note: Owl defines x1 in [0, q-1] in the MODP setting, but x1=0 is naturally excluded
    		 * in the EC setting. Hence we choose x1 from [1, n-1]. 
    		 */
    	    	
    		BigInteger x1 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    		BigInteger x2 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	
    		ECPoint X1 = G.multiply(x1);
    		SchnorrZKP zkpX1 = new SchnorrZKP();
    		zkpX1.generateZKP(G, n, x1, X1, userName);
    	
    		ECPoint X2 = G.multiply(x2);
    		SchnorrZKP zkpX2 = new SchnorrZKP();
    		zkpX2.generateZKP(G, n, x2, X2, userName);
    	    	
    		System.out.println("In the first pass, Client sends to Server ");
    		System.out.println("Username: " + userName);
    		System.out.println("G*x1: "+pointToHex(X1));
    		System.out.println("G*x2: "+pointToHex(X2));
    		System.out.println("KP{x1}: {V="+pointToHex(zkpX1.getV())+"; r="+zkpX1.getr().toString(16)+"}");
    		System.out.println("KP{x2}: {V="+pointToHex(zkpX2.getV())+"; r="+zkpX2.getr().toString(16)+"}");
    		System.out.println("");

    		/*
    		 * Server checks 1) userName is a valid identity (omitted in this demo code) and 2) is different from the server's identity
    		 */

    		if (userName.equals(serverName)) {
    			System.out.println("ERROR: Client and Server identities must be different.");
    			System.exit(0);
    		}
    	    	
    		if (verifyZKP(G, X1, zkpX1.getV(), zkpX1.getr(), userName)) {
    			System.out.println("Server checks KP{x1}: OK");
    		} else {
    			System.out.println("ERROR: invalid KP{x1}.");
    			System.exit(0);
    		}
    	
    		/* 
    		 * Owl defines that the receiver checks X2!=1 in the MODP setting.
    		 * In the EC setting, this translates to checking X2!=infinity, 
    		 * which has been included as part of verifyZKP method. 
    		 */
    		if (verifyZKP(G, X2, zkpX2.getV(), zkpX2.getr(), userName)) {
    			System.out.println("Server checks KP{x2}: OK");
    		} else {
    			System.out.println("ERROR: invalid KP{x2}.");
    			System.exit(0);
    		}
    	
    		/* Second pass:  
    		 * 
    		 * Server chooses x4 randomly from [1, n-1]
    		 * Server -> Client: Server name, X3, G*x4, ZKP{x3}, ZKP{x4}, beta, ZKP{x4 * pi}
    		 */
    	
    		BigInteger x4 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());

    		ECPoint X4 = G.multiply(x4);
    		SchnorrZKP zkpX4 = new SchnorrZKP();
    		zkpX4.generateZKP(G, n, x4, X4, serverName);

    		ECPoint GBeta = X1.add(X2).add(X3); 
    		ECPoint Beta = GBeta.multiply(x4.multiply(pi).mod(n));
				
    		SchnorrZKP zkpX4s = new SchnorrZKP();
    		zkpX4s.generateZKP(GBeta, n, x4.multiply(pi).mod(n), Beta, serverName);

    		System.out.println("\nIn the second pass, Server sends to Client ");
    		System.out.println("Server name: " + serverName);
    		System.out.println("G*x3: "+pointToHex(X3));
    		System.out.println("G*x4: "+pointToHex(X4));
    		System.out.println("KP{x3}: {V="+pointToHex(zkpX3.getV())+"; r="+zkpX3.getr().toString(16)+"}");
    		System.out.println("KP{x4}: {V="+pointToHex(zkpX4.getV())+"; r="+zkpX4.getr().toString(16)+"}");
    		System.out.println("Beta: "+pointToHex(Beta));
    		System.out.println("KP{x4*pi}: {V="+pointToHex(zkpX4s.getV())+"; r="+zkpX4s.getr().toString(16)+"}");    	
    		System.out.println("");
    	
    		/*
    		 * Client checks 1) Server is a valid identity (omitted in this demo code) and 2) is different from her own
    		 */
    		if (serverName.equals(userName)) {
    			System.out.println("ERROR: Username and servername must be different.");
    			System.exit(0);
    		}
    	    	
    		// Client verifies Server's ZKPs.
    		if (verifyZKP(G, X3, zkpX3.getV(), zkpX3.getr(), serverName)) {
    			System.out.println("Client checks KP{x3}: OK");
    		}else {
    			System.out.println("ERROR: invalid KP{x3}.");
    			System.exit(0);
    		}
    	
    		/* 
    		 * Owl defines that the receiver checks X4!=1 in the MODP setting.
    		 * In the EC setting, this translates to checking X4!=infinity, 
    		 * which has been included as part of verifyZKP method. 
    		 */
    		if (verifyZKP(G, X4, zkpX4.getV(), zkpX4.getr(), serverName)) {
    			System.out.println("Client checks KP{x4}: OK");
    		}else {
    			System.out.println("ERROR: invalid KP{x4}.");
    			System.exit(0);
    		}
    	
    		if (verifyZKP(GBeta, Beta, zkpX4s.getV(), zkpX4s.getr(), serverName)) {
    			System.out.println("Client checks KP{x4*s}: OK");
    		}else {
    			System.out.println("ERROR: invalid KP{x4*s}.");
    			System.exit(0);
    		}
    	
    		/* Third pass:  
    		 * 
    		 * Client -> Server: Alpha, ZKP{x2 * pi}, rValue, clientKCTag
    		 * clientKCTag is for realizing explicit key confirmation; it is optional.
    		 */

    		ECPoint GAlpha = X1.add(X3).add(X4); 
    		ECPoint Alpha = GAlpha.multiply(x2.multiply(piLogin).mod(n));
				
    		SchnorrZKP zkpX2s = new SchnorrZKP();
    		zkpX2s.generateZKP(GAlpha, n, x2.multiply(piLogin).mod(n), Alpha, userName);
	
    		ECPoint rawClientKey = Beta.subtract(X4.multiply(x2.multiply(piLogin).mod(n))).multiply(x2);
    		BigInteger clientSessionKey = deriveKey(rawClientKey, "SESS"); // session key
    		BigInteger clientKCKey = deriveKey(rawClientKey, "KC"); // key-confirmation key
    			
    		BigInteger hTranscript = getSHA256(rawClientKey, userName, X1, X2, zkpX1, zkpX2, serverName, 
    			X3, X4, zkpX3, zkpX4, Beta, zkpX4s, Alpha, zkpX2s).mod(n);
    	
    		BigInteger rValue = x1.subtract(tLogin.multiply(hTranscript)).mod(n);
    	
    		// Compute the optional key confirmation tag based on J-PAKE RFC 8236
    		BigInteger clientKCTag = this.deriveHMACTag(clientKCKey, "KC_1_U", userName, serverName, 
    			X1, X2, X3, X4);
    	
    		System.out.println("\nIn the third pass, Client sends to Server: ");

    		System.out.println("Alpha: "+pointToHex(Alpha));
    		System.out.println("KP{x2*s}: {V="+pointToHex(zkpX2s.getV())+", r="+zkpX2s.getr().toString(16)+"}");
    		System.out.println("rValue: " + rValue.toString(16));
    		System.out.println("ClientKCTag (optional): " + clientKCTag.toString(16));
    		System.out.println("");
    	
    		// Server verifies Client's ZKP
    		if (verifyZKP(GAlpha, Alpha, zkpX2s.getV(), zkpX2s.getr(), userName)) {
    			System.out.println("Server checks KP{x2*s}: OK");
    		} else {
    			System.out.println("ERROR: invalid KP{x2*s}.");
    			System.exit(0);
    		}
    	
    		ECPoint rawServerKey = Alpha.subtract(X2.multiply(x4.multiply(pi).mod(n))).multiply(x4);
    		BigInteger serverSessionKey = deriveKey(rawServerKey, "SESS");
    		BigInteger serverKCKey = deriveKey(rawServerKey, "KC");
    	
    		System.out.println("\nClient's raw key (ECPoint): " + pointToHex(rawClientKey));
    		System.out.println("Server's raw key (ECPoint): " + pointToHex(rawServerKey));
    		System.out.println("Client's key confirmation key: " + clientKCKey.toString(16));
    		System.out.println("Server's key confirmation key: " + serverKCKey.toString(16));
    		System.out.println("");
    	
    		BigInteger hServer = getSHA256(rawServerKey, userName, X1, X2, zkpX1, zkpX2, serverName, 
    			X3, X4, zkpX3, zkpX4, Beta, zkpX4s, Alpha, zkpX2s).mod(n);
    	
    		// Server verifies Client's r
    		if (G.multiply(rValue).add(T.multiply(hServer.mod(n))).equals(X1)) {
    			System.out.println("Server checks rValue (for client authentication): OK");
    		}else {
    			System.out.println("ERROR: invalid r (client authentication failed).");
    			System.exit(0);
    		}
    	    	    	
    		// Server verifies Client's key confirmation string
    		BigInteger clientKCTag2 = this.deriveHMACTag(serverKCKey, "KC_1_U", userName, serverName, 
    	    			X1, X2, X3, X4);
    		if (clientKCTag2.equals(clientKCTag)) {
    			System.out.println("Server checks clientKCTag (for explicit key confirmation): OK");
    		} else {
    			System.out.println("ERROR: invalid clientKCTag (explicit key confirmation failed)");
    			System.exit(0);
    		}

    		// Server sends to client key confirmation string (optional)
    		BigInteger serverKCTag = deriveHMACTag(serverKCKey, "KC_1_V", serverName, userName, 
    			X3, X4, X1, X2);
    	
    		System.out.println("\nIn the fourth pass, Sever sends to client an optional key confirmation string ");
    		System.out.println("serverKCTag: " + serverKCTag.toString(16));

    		// Client verifies Server's key confirmation string
    		BigInteger serverKCTag2 = this.deriveHMACTag(clientKCKey, "KC_1_V", serverName, userName, 
    			X3, X4, X1, X2);
    		if (serverKCTag2.equals(serverKCTag)) {
    			System.out.println("Client checks serverKCTag (for explicit key confirmation): OK");
    		} else {
    			System.out.println("ERROR: invalid severKCTag (explicit key confirmation failed).");
    			System.exit(0);
    		}
    			    	
    		System.out.println("\nClient's session key: " + clientSessionKey.toString(16)); 
    		System.out.println("Server's session key: " + serverSessionKey.toString(16)); 
    	
    }

	/*
	 * Converts an EC point to a hexadecimal string
	 * 
	 */
	public String pointToHex(ECPoint X) {
		return new BigInteger(X.getEncoded(true)).toString(16);
	}
	
	/*
	 * Returns a SHA-256 hash as BigInteger from a variable array of objects
	 * Each object must be of type ECPoint, String, BigInteger or SchnoorZKP
	 * Each object is separated by the 32-bit length of the object. 
	 */
	public BigInteger getSHA256(Object... args) {
		
		MessageDigest sha256 = null;
		
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
			for (Object arg : args) {
				if (arg instanceof ECPoint) {
					ECPoint p = (ECPoint) arg;
					sha256.update(intTo4Bytes(p.getEncoded(true).length));
					sha256.update(p.getEncoded(true));
				} else if (arg instanceof String) {
					String s = (String) arg;
					sha256.update(intTo4Bytes(s.getBytes().length));
					sha256.update(s.getBytes());
				} else if (arg instanceof BigInteger) {
					BigInteger i = (BigInteger) arg;
					sha256.update(intTo4Bytes(i.toByteArray().length));					
					sha256.update(i.toByteArray());
				} else if (arg instanceof SchnorrZKP) {
					SchnorrZKP zkp = (SchnorrZKP) arg;
					sha256.update(intTo4Bytes(zkp.getV().getEncoded(true).length));
					sha256.update(zkp.getV().getEncoded(true));
					sha256.update(intTo4Bytes(zkp.getr().toByteArray().length));
					sha256.update(zkp.getr().toByteArray());
				} else {
					throw new IllegalArgumentException("Invalid object type passed to getSHA256");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		// signum = 1 ensures a positive output
		return new BigInteger(1, sha256.digest());
	}

    /*
     * Here, we represent the ZKP as (V, r), following the elliptic curve J-PAKE implementation
     * Alternatively, we can represent the ZKP as (h, r). This makes no difference in computation cost.
     * In the EC setting, the size of (h, r) is almost the same as (V, r) when V is in the compressed form.
     * In the MODP setting, (h, r) is far more compact in size, and hence should be used instead of (V, r). 
     */
    public boolean verifyZKP(ECPoint generator, ECPoint X, ECPoint V, BigInteger r, String userID) {
    	
    		/* ZKP: {V=G*v, r} */    	    	
    		BigInteger h = getSHA256(generator, V, X, userID);
    	
    		/* Public key validation based on the following paper (Sec 3)
    		 * Antipa, A., Brown, D., Menezes, A., Struik, R. and Vanstone, S., 
    		 * "Validation of elliptic curve public keys," PKC, 2002
    		 * https://iacr.org/archive/pkc2003/25670211/25670211.pdf
    		 */
    	
    		// 1. X != infinity
    		if (X.isInfinity()){
    			return false;
    		}
    	
    		// 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
    		if (X.normalize().getXCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
    			X.normalize().getXCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1 ||
    			X.normalize().getYCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
    			X.normalize().getYCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1) {
    			return false;
    		}
    				
    		// 3. Check X lies on the curve
    		try {
    			ecCurve.decodePoint(X.getEncoded(true));
    		}catch(Exception e){
    			e.printStackTrace();
    			return false;
    		}
    	
    		// 4. Check that nX = infinity.
    		// It is replaced by the check that coFactor*X is not infinity (i.e., X is not in a small subgroup)
    		if (X.multiply(coFactor).isInfinity()) { 
    			return false;
    		}
    	
    		// Now check if V = G*r + X*h. 
    		// Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
    		if (V.equals(generator.multiply(r).add(X.multiply(h.mod(n))))) {
    			return true;
    		} else {
    			return false;
    		}
    }
    
    /*
     * Represent an integer as 4 bytes
     */
    public byte[] intTo4Bytes (int length) {
    		
    		return ByteBuffer.allocate(4).putInt(length).array();
    		    	
    }
    
    /*
     * Returns a derived key = H(rawKey || otherInput). 
     * As an example, we simply use SHA-256 as a key derivation function
     */
    public BigInteger deriveKey (ECPoint rawKey, String otherInput) {
    		
		return getSHA256(rawKey, otherInput);    	
    }
    
    /*
     * Returns a HMAC tag for key confirmation based on J-PAKE RFC 8236
     * tag = HMAC(key, messageString || senderID || receiver ID || sender data || receiver data) 
     * We use a messengeString "KC_1_U" for client and "KC_1_V" for server
     */
    public BigInteger deriveHMACTag(BigInteger key, String messageString, String senderID,
    		String receiverID, ECPoint senderKey1, ECPoint senderKey2, ECPoint receiverKey1, 
    		ECPoint receiverKey2) {
    	
    		BigInteger macTag = null;
    	
    		try {
    			
    			SecretKeySpec secretKeySpec = new SecretKeySpec(key.toByteArray(), "HmacSHA256");
    			Mac mac = Mac.getInstance("HmacSHA256");
    			mac.init(secretKeySpec);
    			
    			mac.update(intTo4Bytes(messageString.getBytes().length));
    			mac.update(messageString.getBytes());
    			
    			mac.update(intTo4Bytes(senderID.getBytes().length));
    			mac.update(senderID.getBytes());
    			
    			mac.update(intTo4Bytes(receiverID.getBytes().length));
    			mac.update(receiverID.getBytes());
    			
    			mac.update(intTo4Bytes(senderKey1.getEncoded(true).length));
    			mac.update(senderKey1.getEncoded(true));
    			
    			mac.update(intTo4Bytes(senderKey2.getEncoded(true).length));
    			mac.update(senderKey2.getEncoded(true));
    			
    			mac.update(intTo4Bytes(receiverKey1.getEncoded(true).length));
    			mac.update(receiverKey1.getEncoded(true));
    			
    			mac.update(intTo4Bytes(receiverKey2.getEncoded(true).length));
    			mac.update(receiverKey2.getEncoded(true));
    			
    			macTag = new BigInteger(1, mac.doFinal()); // 1 to ensure a positive value 
    			
    		}catch(Exception e) {
    			e.printStackTrace();
    		}
    		
    		return macTag;
    			
    }
    
    private class SchnorrZKP {
    	
    		private ECPoint V = null;
    		private BigInteger r = null;
    			
    		private SchnorrZKP () {
    			// constructor
    		}
    	
    		/*
    		 * Here, we follow EC-J-PAKE and use (V, r) as the ZKP. This has little difference to using (h, r)
    		 * However, in a MOPD setting, (h, r) should be used as the size will be more compact
    		 */    		
    		private void generateZKP (ECPoint generator, BigInteger n, BigInteger x, ECPoint X, String userID) {

    			/* Generate a random v from [1, n-1], and compute V = G*v */
    			BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
        			n.subtract(BigInteger.ONE), new SecureRandom());
    			V = generator.multiply(v);
        	
    			BigInteger h = getSHA256(generator, V, X, userID); // h

    			r = v.subtract(x.multiply(h)).mod(n); // r = v-x*h mod n   	
    		}
    	
    		private ECPoint getV() {
    			return V;
    		}
    	
    		private BigInteger getr() {
    			return r;
    		}
    }
}