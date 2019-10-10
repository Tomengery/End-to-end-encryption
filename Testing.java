import static org.whispersystems.curve25519.Curve25519.BEST;

import java.util.Base64;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.AliceSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.BobSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.RatchetingSession;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;
import org.whispersystems.libsignal.state.impl.InMemoryIdentityKeyStore;
import org.whispersystems.libsignal.state.impl.InMemoryPreKeyStore;
import org.whispersystems.libsignal.state.impl.InMemorySessionStore;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.state.impl.InMemorySignedPreKeyStore;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Medium;
import org.whispersystems.libsignal.util.guava.Optional;

public class Testing {
	
    static ECKeyPair       aliceIdentityKeyPair = Curve.generateKeyPair();
    static IdentityKeyPair aliceIdentityKey     = new IdentityKeyPair(new IdentityKey (aliceIdentityKeyPair.getPublicKey()),
                                                               aliceIdentityKeyPair.getPrivateKey());
    static ECKeyPair       aliceBaseKey         = Curve.generateKeyPair();
    ECKeyPair       aliceEphemeralKey    = Curve.generateKeyPair();

    ECKeyPair alicePreKey = aliceBaseKey;   // use?? 

    static ECKeyPair       bobIdentityKeyPair = Curve.generateKeyPair();
    static IdentityKeyPair bobIdentityKey       = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                                               bobIdentityKeyPair.getPrivateKey());
    static ECKeyPair       bobBaseKey           = Curve.generateKeyPair();
    static ECKeyPair       bobEphemeralKey      = bobBaseKey;

    ECKeyPair       bobPreKey            = Curve.generateKeyPair();  //use??

	  
	public static void main(String[] args) {
		try{
			SessionRecord aliceSessionRecord = new SessionRecord(); 
			//Session from alice side where bob ratchet key is his signed pre key
			AliceSignalProtocolParameters aliceParameters = AliceSignalProtocolParameters.newBuilder()
                      .setOurBaseKey(aliceBaseKey)  // alice ephemeral key?? but not equal
                      .setOurIdentityKey(aliceIdentityKey)
                      .setTheirOneTimePreKey(Optional.<ECPublicKey>absent())
                      .setTheirRatchetKey(bobEphemeralKey.getPublicKey()) // equal to bob signed pre key
                      .setTheirSignedPreKey(bobBaseKey.getPublicKey())   // bob signed pre key
                      .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                      .create();
			  RatchetingSession.initializeSession(aliceSessionRecord.getSessionState(), aliceParameters);  
			  
			  SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore(); // identity key pair and registration ID 
			  aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord); //signal protocol address is string name and device id 
			  SessionCipher     aliceCipher    = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));// alice store and remote address
			 			  		    			    			    
			    
			SessionRecord bobSessionRecord   = new SessionRecord();
			BobSignalProtocolParameters bobParameters = BobSignalProtocolParameters.newBuilder()
					//Decryption from bob side where bob ratchet key is her signed pre key
                    .setOurRatchetKey(bobEphemeralKey)
                    .setOurSignedPreKey(bobBaseKey)
                    .setOurIdentityKey(bobIdentityKey)
                    .setOurOneTimePreKey(Optional.<ECKeyPair>absent())
                    .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                    .setTheirBaseKey(aliceBaseKey.getPublicKey())   //should it be alice ephemeralkey
                    .create();
		
		RatchetingSession.initializeSession(bobSessionRecord.getSessionState(), bobParameters);
		
		SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
	    bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);
	    
	    SessionCipher     bobCipher      = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));
	    
	    
	    
	    
	    
	    byte[]            alicePlaintext = "This is a plaintext message for checking.".getBytes();
	    byte[]            alicePlaintext2 = "This is a plaintext message 2.".getBytes();
	    byte[]            alicePlaintext3 = "This is a plaintext message 3.".getBytes();
	    byte[]            alicePlaintext4 = "This is a plaintext message 4.".getBytes();
	    byte[]            alicePlaintext5 = "This is a plaintext message 5.".getBytes();
	    byte[]            alicePlaintext6 = "This is a plaintext message 6.".getBytes();
	    byte[]            alicePlaintext7 = "This is a plaintext message 7.".getBytes();
	    byte[]            alicePlaintext8 = "This is a plaintext message 8.".getBytes();
	    byte[]            alicePlaintext9 = "This is a plaintext message 9.".getBytes();
	    
	    byte[]            bobPlaintext = "BOB This is a plaintext message bob's checking.".getBytes();
	    byte[]            bobPlaintext2 = "BOB This is a plaintext message 2.".getBytes();  
		byte[]            bobPlaintext3 = "This is a plaintext message 3.".getBytes();
	    
	    
	    
	    CiphertextMessage alicemessage        = aliceCipher.encrypt(alicePlaintext);
	    byte[]            bob1   = bobCipher.decrypt(new SignalMessage(alicemessage.serialize()));
	    /*for(int i=0;i<alicePlaintext.length;i++) // ascii value of plain text
	    {
	    	System.out.println(alicePlaintext[i]);
	    }*/
	    /*for(int i=0;i<bob1.length;i++) // ascii value of decrypted msg
	    {
	    	System.out.println(bob1[i]);
	    }*/
	    
	    System.out.println(new String(bob1));
	    
	    CiphertextMessage alicemessage2        = aliceCipher.encrypt(alicePlaintext2);
	    CiphertextMessage alicemessage3        = aliceCipher.encrypt(alicePlaintext2);
	    CiphertextMessage alicemessage4        = aliceCipher.encrypt(alicePlaintext2);
	    CiphertextMessage alicemessage7        = aliceCipher.encrypt(alicePlaintext2);
	    CiphertextMessage alicemessage8        = aliceCipher.encrypt(alicePlaintext2);
	    CiphertextMessage alicemessage9        = aliceCipher.encrypt(alicePlaintext2);
	    
	    
	    
	    CiphertextMessage bobmessage        = bobCipher.encrypt(bobPlaintext);
	    byte[]            alice   = aliceCipher.decrypt(new SignalMessage(bobmessage.serialize()));
		System.out.println(new String(alice));
	    
		
		
	    CiphertextMessage alicemessage5        = aliceCipher.encrypt(alicePlaintext4);
	    byte[]            bob4   = bobCipher.decrypt(new SignalMessage(alicemessage5.serialize()));
	    System.out.println(new String(bob4));
	    
	    CiphertextMessage bobmessage2        = bobCipher.encrypt(bobPlaintext2);
	    byte[]            alice2   = aliceCipher.decrypt(new SignalMessage(bobmessage2.serialize()));
		System.out.println(new String(alice2));
	    
	    /*CiphertextMessage alicemessage5        = aliceCipher.encrypt(alicePlaintext5);
	    CiphertextMessage alicemessage6        = aliceCipher.encrypt(alicePlaintext6);*/

	    byte[]            bob8   = bobCipher.decrypt(new SignalMessage(alicemessage9.serialize()));
	    System.out.println(new String(bob8));
	    
	    byte[]            bob2   = bobCipher.decrypt(new SignalMessage(alicemessage2.serialize()));
	    System.out.println(new String(bob2));
	    byte[]            bob3   = bobCipher.decrypt(new SignalMessage(alicemessage3.serialize()));
	    System.out.println(new String(bob2));
	    
	    byte[]            bob5   = bobCipher.decrypt(new SignalMessage(alicemessage4.serialize()));
	    System.out.println(new String(bob5));
	    
	    
	    byte[]            bob6   = bobCipher.decrypt(new SignalMessage(alicemessage7.serialize()));
	    System.out.println(new String(bob6));
	    byte[]            bob7   = bobCipher.decrypt(new SignalMessage(alicemessage8.serialize()));
	    System.out.println(new String(bob7));
	    
	
	    
	    
	    
	   
	    
	    
	    
		
	    			  
		}catch(Exception e){
			e.printStackTrace();
		}		
	}
}
