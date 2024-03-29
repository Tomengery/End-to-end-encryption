import java.util.HashSet;
import java.util.Set;

import org.whispersystems.libsignal.DecryptionCallback;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SessionBuilder;

import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;


import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Pair;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Pair;

import java.util.HashSet;
import java.util.Set;


public class SessionBuilderTest {
	private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1); 
	#recipient name + device id tuple
	  private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("+14152222222", 1);

	  public void testBasicPreKeyV2()
	      throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, UntrustedIdentityException, NoSessionException {
	    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

	    SignalProtocolStore bobStore      = new TestInMemorySignalProtocolStore();
	    ECKeyPair    bobPreKeyPair = Curve.generateKeyPair();
	    PreKeyBundle bobPreKey     = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
	                                                  31337, bobPreKeyPair.getPublicKey(),
	                                                  0, null, null,
	                                                  bobStore.getIdentityKeyPair().getPublicKey());

	    try {
	      aliceSessionBuilder.process(bobPreKey);
	      
	      throw new AssertionError("Should fail with missing unsigned prekey!");
	    } catch (InvalidKeyException e) {
	      // Good!
	    	
	    	
	      return;
	    }
	  }

	  public void testBasicPreKeyV3()
	      throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, UntrustedIdentityException, NoSessionException {
	    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

	    final SignalProtocolStore bobStore                 = new TestInMemorySignalProtocolStore();
	          ECKeyPair    bobPreKeyPair            = Curve.generateKeyPair();
	          ECKeyPair    bobSignedPreKeyPair      = Curve.generateKeyPair();
	          byte[]       bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
	                                                                           bobSignedPreKeyPair.getPublicKey().serialize());

	    PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
	                                              31337, bobPreKeyPair.getPublicKey(),
	                                              22, bobSignedPreKeyPair.getPublicKey(),
	                                              bobSignedPreKeySignature,
	                                              bobStore.getIdentityKeyPair().getPublicKey());

	    aliceSessionBuilder.process(bobPreKey);

	    System.out.println(aliceStore.containsSession(BOB_ADDRESS));
	    System.out.println(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);

	    final String            originalMessage    = "L'homme est condamné à être libre";
	          SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	          CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

	    System.out.println(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

	    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
	    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
	    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
	    byte[] plaintext = bobSessionCipher.decrypt(incomingMessage, new DecryptionCallback() {
	      @Override
	      public void handlePlaintext(byte[] plaintext) {
	        System.out.println(originalMessage.equals(new String(plaintext)));
	        System.out.println(bobStore.containsSession(ALICE_ADDRESS));
	      }
	    });

	    System.out.println(bobStore.containsSession(ALICE_ADDRESS));
	    System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);
	    System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey() != null);
	    System.out.println(originalMessage.equals(new String(plaintext)));

	    CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
	    System.out.println(bobOutgoingMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
	    System.out.println(new String(alicePlaintext).equals(originalMessage));

	    runInteraction(aliceStore, bobStore);

	    aliceStore          = new TestInMemorySignalProtocolStore();
	    aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
	    aliceSessionCipher  = new SessionCipher(aliceStore, BOB_ADDRESS);

	    bobPreKeyPair            = Curve.generateKeyPair();
	    bobSignedPreKeyPair      = Curve.generateKeyPair();
	    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(), bobSignedPreKeyPair.getPublicKey().serialize());
	    bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(),
	                                 1, 31338, bobPreKeyPair.getPublicKey(),
	                                 23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
	                                 bobStore.getIdentityKeyPair().getPublicKey());

	    bobStore.storePreKey(31338, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
	    bobStore.storeSignedPreKey(23, new SignedPreKeyRecord(23, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));
	    aliceSessionBuilder.process(bobPreKey);

	    outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

	    try {
	      plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
	      throw new AssertionError("shouldn't be trusted!");
	    } catch (UntrustedIdentityException uie) {
	      bobStore.saveIdentity(ALICE_ADDRESS, new PreKeySignalMessage(outgoingMessage.serialize()).getIdentityKey());
	    }

	    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
	    System.out.println(new String(plaintext).equals(originalMessage));

	    bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
	                                 31337, Curve.generateKeyPair().getPublicKey(),
	                                 23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
	                                 aliceStore.getIdentityKeyPair().getPublicKey());

	    try {
	      aliceSessionBuilder.process(bobPreKey);
	      throw new AssertionError("shoulnd't be trusted!");
	    } catch (UntrustedIdentityException uie) {
	      // good
	    }
	  }

	  public void testBadSignedPreKeySignature() throws InvalidKeyException, UntrustedIdentityException {
	    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

	    IdentityKeyStore bobIdentityKeyStore = new TestInMemoryIdentityKeyStore();

	    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
	    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
	    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobIdentityKeyStore.getIdentityKeyPair().getPrivateKey(),
	                                                                  bobSignedPreKeyPair.getPublicKey().serialize());


	    for (int i=0;i<bobSignedPreKeySignature.length * 8;i++) {
	      byte[] modifiedSignature = new byte[bobSignedPreKeySignature.length];
	      System.arraycopy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.length);

	      modifiedSignature[i/8] ^= (0x01 << (i % 8));

	      PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.getLocalRegistrationId(), 1,
	                                                31337, bobPreKeyPair.getPublicKey(),
	                                                22, bobSignedPreKeyPair.getPublicKey(), modifiedSignature,
	                                                bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

	      try {
	        aliceSessionBuilder.process(bobPreKey);
	        throw new AssertionError("Accepted modified device key signature!");
	      } catch (InvalidKeyException ike) {
	        // good
	      }
	    }

	    PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.getLocalRegistrationId(), 1,
	                                              31337, bobPreKeyPair.getPublicKey(),
	                                              22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
	                                              bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

	    aliceSessionBuilder.process(bobPreKey);
	  }

	  public void testRepeatBundleMessageV2() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
	    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

	    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

	    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
	    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
	    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
	                                                                  bobSignedPreKeyPair.getPublicKey().serialize());

	    PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
	                                              31337, bobPreKeyPair.getPublicKey(),
	                                              0, null, null,
	                                              bobStore.getIdentityKeyPair().getPublicKey());

	    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
	    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

	    try {
	      aliceSessionBuilder.process(bobPreKey);
	      throw new AssertionError("Should fail with missing signed prekey!");
	    } catch (InvalidKeyException e) {
	      // Good!
	      return;
	    }
	  }

	  public void testRepeatBundleMessageV3() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
	    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

	    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

	    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
	    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
	    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
	                                                                  bobSignedPreKeyPair.getPublicKey().serialize());

	    PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
	                                              31337, bobPreKeyPair.getPublicKey(),
	                                              22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
	                                              bobStore.getIdentityKeyPair().getPublicKey());

	    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
	    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

	    aliceSessionBuilder.process(bobPreKey);

	    String            originalMessage    = "L'homme est condamné à être libre";
	    SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());
	    CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(originalMessage.getBytes());

	    System.out.println(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);
	    System.out.println(outgoingMessageTwo.getType() == CiphertextMessage.PREKEY_TYPE);

	    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.serialize());

	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

	    byte[]        plaintext        = bobSessionCipher.decrypt(incomingMessage);
	    System.out.println(new String(plaintext));

	    CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

	    byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
	    System.out.println(originalMessage.equals(new String(alicePlaintext)));

	    // The test

	    PreKeySignalMessage incomingMessageTwo = new PreKeySignalMessage(outgoingMessageTwo.serialize());

	    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(incomingMessageTwo.serialize()));
	    System.out.println(originalMessage.equals(new String(plaintext)));

	    bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
	    alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
	    System.out.println(originalMessage.equals(new String(alicePlaintext)));

	  }

	  public void testBadMessageBundle() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, LegacyMessageException, InvalidKeyIdException {
	    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

	    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

	    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
	    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
	    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
	                                                                  bobSignedPreKeyPair.getPublicKey().serialize());

	    PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
	                                              31337, bobPreKeyPair.getPublicKey(),
	                                              22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
	                                              bobStore.getIdentityKeyPair().getPublicKey());

	    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
	    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

	    aliceSessionBuilder.process(bobPreKey);

	    String            originalMessage    = "L'homme est condamné à être libre";
	    SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

	    System.out.println(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

	    byte[] goodMessage = outgoingMessageOne.serialize();
	    byte[] badMessage  = new byte[goodMessage.length];
	    System.arraycopy(goodMessage, 0, badMessage, 0, badMessage.length);

	    badMessage[badMessage.length-10] ^= 0x01;

	    PreKeySignalMessage incomingMessage  = new PreKeySignalMessage(badMessage);
	    SessionCipher        bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

	    byte[] plaintext = new byte[0];

	    try {
	      plaintext = bobSessionCipher.decrypt(incomingMessage);
	      throw new AssertionError("Decrypt should have failed!");
	    } catch (InvalidMessageException e) {
	      // good.
	    }

	    System.out.println(bobStore.containsPreKey(31337));

	    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(goodMessage));

	    System.out.println(originalMessage.equals(new String(plaintext)));
	    System.out.println(!bobStore.containsPreKey(31337));
	  }

	  public void testOptionalOneTimePreKey() throws Exception {
	    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

	    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

	    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
	    ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
	    byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
	                                                                  bobSignedPreKeyPair.getPublicKey().serialize());

	    PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
	                                              0, null,
	                                              22, bobSignedPreKeyPair.getPublicKey(),
	                                              bobSignedPreKeySignature,
	                                              bobStore.getIdentityKeyPair().getPublicKey());

	    aliceSessionBuilder.process(bobPreKey);

	    System.out.println(aliceStore.containsSession(BOB_ADDRESS));
	    System.out.println(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);

	    String            originalMessage    = "L'homme est condamné à être libre";
	    SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

	    System.out.println(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

	    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
	    System.out.println(!incomingMessage.getPreKeyId().isPresent());

	    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
	    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
	    byte[]        plaintext        = bobSessionCipher.decrypt(incomingMessage);

	    System.out.println(bobStore.containsSession(ALICE_ADDRESS));
	    System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);
	    System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey() != null);
	    System.out.println(originalMessage.equals(new String(plaintext)));
	  }


	  private void runInteraction(SignalProtocolStore aliceStore, SignalProtocolStore bobStore)
	      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSessionException, UntrustedIdentityException
	  {
	    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    SessionCipher bobSessionCipher   = new SessionCipher(bobStore, ALICE_ADDRESS);

	    String originalMessage = "smert ze smert";
	    CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

	    System.out.println(aliceMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] plaintext = bobSessionCipher.decrypt(new SignalMessage(aliceMessage.serialize()));
	    System.out.println(new String(plaintext).equals(originalMessage));

	    CiphertextMessage bobMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

	    System.out.println(bobMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    plaintext = aliceSessionCipher.decrypt(new SignalMessage(bobMessage.serialize()));
	    System.out.println(new String(plaintext).equals(originalMessage));

	    for (int i=0;i<10;i++) {
	      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
	                               "We mean that man first of all exists, encounters himself, " +
	                               "surges up in the world--and defines himself aftward. " + i);
	      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

	      byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
	      System.out.println(new String(loopingPlaintext).equals(loopingMessage));
	    }

	    for (int i=0;i<10;i++) {
	      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
	                               "We mean that man first of all exists, encounters himself, " +
	                               "surges up in the world--and defines himself aftward. " + i);
	      CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

	      byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
	      System.out.println(new String(loopingPlaintext).equals(loopingMessage));
	    }

	    Set<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<>();

	    for (int i=0;i<10;i++) {
	      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
	                               "We mean that man first of all exists, encounters himself, " +
	                               "surges up in the world--and defines himself aftward. " + i);
	      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

	      aliceOutOfOrderMessages.add(new Pair<>(loopingMessage, aliceLoopingMessage));
	    }

	    for (int i=0;i<10;i++) {
	      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
	                               "We mean that man first of all exists, encounters himself, " +
	                               "surges up in the world--and defines himself aftward. " + i);
	      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

	      byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
	      System.out.println(new String(loopingPlaintext).equals(loopingMessage));
	    }

	    for (int i=0;i<10;i++) {
	      String loopingMessage = ("You can only desire based on what you know: " + i);
	      CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

	      byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
	      System.out.println(new String(loopingPlaintext).equals(loopingMessage));
	    }

	    for (Pair<String, CiphertextMessage> aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
	      byte[] outOfOrderPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceOutOfOrderMessage.second().serialize()));
	      System.out.println(new String(outOfOrderPlaintext).equals(aliceOutOfOrderMessage.first()));
	    }
	  }

	  
	  public static void main(String[] args)  {
		SessionBuilderTest builder = new SessionBuilderTest();
		try {
			builder.testBasicPreKeyV3();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidVersionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidMessageException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyIdException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DuplicateMessageException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (LegacyMessageException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UntrustedIdentityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSessionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
