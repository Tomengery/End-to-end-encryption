import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

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
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Medium;

public class SimultaneousInitiateTests {
	 private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("+14151231234", 1);
	  private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14159998888", 1);

	  private static final ECKeyPair aliceSignedPreKey = Curve.generateKeyPair();
	  private static final ECKeyPair bobSignedPreKey   = Curve.generateKeyPair();

	  private static final int aliceSignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
	  private static final int bobSignedPreKeyId   = new Random().nextInt(Medium.MAX_VALUE);

	  public void testBasicSimultaneousInitiate()
	      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
	      InvalidMessageException, DuplicateMessageException, LegacyMessageException,
	      InvalidKeyIdException, NoSessionException
	  {
	    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
	    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
	    
	    System.out.println(aliceStore.getLocalRegistrationId());
	    System.out.println(Base64.getEncoder().encodeToString(aliceStore.getIdentityKeyPair().getPrivateKey().serialize()));
	    System.out.println(bobStore.getLocalRegistrationId());
	    System.out.println(Base64.getEncoder().encodeToString(bobStore.getIdentityKeyPair().getPrivateKey().serialize()));

	    PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
	    PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
	    SessionBuilder bobSessionBuilder   = new SessionBuilder(bobStore, ALICE_ADDRESS);

	    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

	    aliceSessionBuilder.process(bobPreKeyBundle);
	    bobSessionBuilder.process(alicePreKeyBundle);

	    CiphertextMessage messageForBob   = aliceSessionCipher.encrypt("hey there".getBytes());
	   // CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

	    System.out.println(messageForBob.getType() == CiphertextMessage.PREKEY_TYPE);
	    //System.out.println(messageForAlice.getType() == CiphertextMessage.PREKEY_TYPE);

	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    //byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
	    byte[] bobPlaintext   = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

	    //System.out.println(new String(alicePlaintext).equals("sample message"));
	    System.out.println(new String(bobPlaintext).equals("hey there"));

	    System.out.println(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
	    System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

	    System.out.println(aliceResponse.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

	    System.out.println(new String(responsePlaintext).equals("second message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

	    System.out.println(finalMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

	    System.out.println(new String(finalPlaintext).equals("third message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));
	  }

	  public void testLostSimultaneousInitiate() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, LegacyMessageException, InvalidKeyIdException, NoSessionException {
	    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
	    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

	    PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
	    PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
	    SessionBuilder bobSessionBuilder   = new SessionBuilder(bobStore, ALICE_ADDRESS);

	    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

	    aliceSessionBuilder.process(bobPreKeyBundle);
	    bobSessionBuilder.process(alicePreKeyBundle);

	    CiphertextMessage messageForBob   = aliceSessionCipher.encrypt("hey there".getBytes());
	    CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

	    System.out.println(messageForBob.getType() == CiphertextMessage.PREKEY_TYPE);
	    System.out.println(messageForAlice.getType() == CiphertextMessage.PREKEY_TYPE);

	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    byte[] bobPlaintext   = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

	    System.out.println(new String(bobPlaintext).equals("hey there"));
	    System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

	    CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

	    System.out.println(aliceResponse.getType() == CiphertextMessage.PREKEY_TYPE);

	    byte[] responsePlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(aliceResponse.serialize()));

	    System.out.println(new String(responsePlaintext).equals("second message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

	    System.out.println(finalMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

	    System.out.println(new String(finalPlaintext).equals("third message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));
	  }

	  public void testSimultaneousInitiateLostMessage()
	      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
	      InvalidMessageException, DuplicateMessageException, LegacyMessageException,
	      InvalidKeyIdException, NoSessionException
	  {
	    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
	    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

	    PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
	    PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
	    SessionBuilder bobSessionBuilder   = new SessionBuilder(bobStore, ALICE_ADDRESS);

	    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

	    aliceSessionBuilder.process(bobPreKeyBundle);
	    bobSessionBuilder.process(alicePreKeyBundle);

	    CiphertextMessage messageForBob   = aliceSessionCipher.encrypt("hey there".getBytes());
	    CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

	    System.out.println(messageForBob.getType() == CiphertextMessage.PREKEY_TYPE);
	    System.out.println(messageForAlice.getType() == CiphertextMessage.PREKEY_TYPE);

	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
	    byte[] bobPlaintext   = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

	    System.out.println(new String(alicePlaintext).equals("sample message"));
	    System.out.println(new String(bobPlaintext).equals("hey there"));

	    System.out.println(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
	    System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

	    System.out.println(aliceResponse.getType() == CiphertextMessage.WHISPER_TYPE);

//	    byte[] responsePlaintext = bobSessionCipher.decrypt(new WhisperMessage(aliceResponse.serialize()));
	//
//	    System.out.println(new String(responsePlaintext).equals("second message"));
//	    System.out.println(isSessionIdEqual(aliceStore, bobStore));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

	    System.out.println(finalMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

	    System.out.println(new String(finalPlaintext).equals("third message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));
	  }

	  public void testSimultaneousInitiateRepeatedMessages()
	      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
	      InvalidMessageException, DuplicateMessageException, LegacyMessageException,
	      InvalidKeyIdException, NoSessionException
	  {
	    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
	    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

	    PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
	    PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
	    SessionBuilder bobSessionBuilder   = new SessionBuilder(bobStore, ALICE_ADDRESS);

	    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

	    aliceSessionBuilder.process(bobPreKeyBundle);
	    bobSessionBuilder.process(alicePreKeyBundle);

	    CiphertextMessage messageForBob   = aliceSessionCipher.encrypt("hey there".getBytes());
	    CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

	    System.out.println(messageForBob.getType() == CiphertextMessage.PREKEY_TYPE);
	    System.out.println(messageForAlice.getType() == CiphertextMessage.PREKEY_TYPE);

	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
	    byte[] bobPlaintext   = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

	    System.out.println(new String(alicePlaintext).equals("sample message"));
	    System.out.println(new String(bobPlaintext).equals("hey there"));

	    System.out.println(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
	    System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    for (int i=0;i<50;i++) {
	      CiphertextMessage messageForBobRepeat   = aliceSessionCipher.encrypt("hey there".getBytes());
	      CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

	      System.out.println(messageForBobRepeat.getType() == CiphertextMessage.WHISPER_TYPE);
	      System.out.println(messageForAliceRepeat.getType() == CiphertextMessage.WHISPER_TYPE);

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));

	      byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
	      byte[] bobPlaintextRepeat   = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

	      System.out.println(new String(alicePlaintextRepeat).equals("sample message"));
	      System.out.println(new String(bobPlaintextRepeat).equals("hey there"));

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));
	    }

	    CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

	    System.out.println(aliceResponse.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

	    System.out.println(new String(responsePlaintext).equals("second message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

	    System.out.println(finalMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

	    System.out.println(new String(finalPlaintext).equals("third message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));
	  }

	  public void testRepeatedSimultaneousInitiateRepeatedMessages()
	      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
	      InvalidMessageException, DuplicateMessageException, LegacyMessageException,
	      InvalidKeyIdException, NoSessionException
	  {
	    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
	    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();


	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
	    SessionBuilder bobSessionBuilder   = new SessionBuilder(bobStore, ALICE_ADDRESS);

	    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

	    for (int i=0;i<15;i++) {
	      PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
	      PreKeyBundle bobPreKeyBundle   = createBobPreKeyBundle(bobStore);

	      aliceSessionBuilder.process(bobPreKeyBundle);
	      bobSessionBuilder.process(alicePreKeyBundle);

	      CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
	      CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

	      System.out.println(messageForBob.getType() == CiphertextMessage.PREKEY_TYPE);
	      System.out.println(messageForAlice.getType() == CiphertextMessage.PREKEY_TYPE);

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));

	      byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
	      byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

	      System.out.println(new String(alicePlaintext).equals("sample message"));
	      System.out.println(new String(bobPlaintext).equals("hey there"));

	      System.out.println(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
	      System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));
	    }

	    for (int i=0;i<50;i++) {
	      CiphertextMessage messageForBobRepeat   = aliceSessionCipher.encrypt("hey there".getBytes());
	      CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

	      System.out.println(messageForBobRepeat.getType() == CiphertextMessage.WHISPER_TYPE);
	      System.out.println(messageForAliceRepeat.getType() == CiphertextMessage.WHISPER_TYPE);

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));

	      byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
	      byte[] bobPlaintextRepeat   = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

	      System.out.println(new String(alicePlaintextRepeat).equals("sample message"));
	      System.out.println(new String(bobPlaintextRepeat).equals("hey there"));

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));
	    }

	    CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

	    System.out.println(aliceResponse.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

	    System.out.println(new String(responsePlaintext).equals("second message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

	    System.out.println(finalMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

	    System.out.println(new String(finalPlaintext).equals("third message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));
	  }

	  public void testRepeatedSimultaneousInitiateLostMessageRepeatedMessages()
	      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
	      InvalidMessageException, DuplicateMessageException, LegacyMessageException,
	      InvalidKeyIdException, NoSessionException
	  {
	    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
	    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();


	    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
	    SessionBuilder bobSessionBuilder   = new SessionBuilder(bobStore, ALICE_ADDRESS);

	    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
	    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

//	    PreKeyBundle aliceLostPreKeyBundle = createAlicePreKeyBundle(aliceStore);
	    PreKeyBundle bobLostPreKeyBundle   = createBobPreKeyBundle(bobStore);

	    aliceSessionBuilder.process(bobLostPreKeyBundle);
//	    bobSessionBuilder.process(aliceLostPreKeyBundle);

	    CiphertextMessage lostMessageForBob   = aliceSessionCipher.encrypt("hey there".getBytes());
//	    CiphertextMessage lostMessageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

	    for (int i=0;i<15;i++) {
	      PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
	      PreKeyBundle bobPreKeyBundle   = createBobPreKeyBundle(bobStore);

	      aliceSessionBuilder.process(bobPreKeyBundle);
	      bobSessionBuilder.process(alicePreKeyBundle);

	      CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
	      CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

	      System.out.println(messageForBob.getType() == CiphertextMessage.PREKEY_TYPE);
	      System.out.println(messageForAlice.getType() == CiphertextMessage.PREKEY_TYPE);

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));

	      byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
	      byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

	      System.out.println(new String(alicePlaintext).equals("sample message"));
	      System.out.println(new String(bobPlaintext).equals("hey there"));

	      System.out.println(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
	      System.out.println(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));
	    }

	    for (int i=0;i<50;i++) {
	      CiphertextMessage messageForBobRepeat   = aliceSessionCipher.encrypt("hey there".getBytes());
	      CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

	      System.out.println(messageForBobRepeat.getType() == CiphertextMessage.WHISPER_TYPE);
	      System.out.println(messageForAliceRepeat.getType() == CiphertextMessage.WHISPER_TYPE);

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));

	      byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
	      byte[] bobPlaintextRepeat   = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

	      System.out.println(new String(alicePlaintextRepeat).equals("sample message"));
	      System.out.println(new String(bobPlaintextRepeat).equals("hey there"));

	      System.out.println(isSessionIdEqual(aliceStore, bobStore));
	    }

	    CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

	    System.out.println(aliceResponse.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

	    System.out.println(new String(responsePlaintext).equals("second message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

	    System.out.println(finalMessage.getType() == CiphertextMessage.WHISPER_TYPE);

	    byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

	    System.out.println(new String(finalPlaintext).equals("third message"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    byte[] lostMessagePlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(lostMessageForBob.serialize()));
	    System.out.println(new String(lostMessagePlaintext).equals("hey there"));

	    System.out.println(isSessionIdEqual(aliceStore, bobStore));

	    CiphertextMessage blastFromThePast          = bobSessionCipher.encrypt("unexpected!".getBytes());
	    byte[]            blastFromThePastPlaintext = aliceSessionCipher.decrypt(new SignalMessage(blastFromThePast.serialize()));

	    System.out.println(new String(blastFromThePastPlaintext).equals("unexpected!"));
	    System.out.println(isSessionIdEqual(aliceStore, bobStore));
	  }

	  private boolean isSessionIdEqual(SignalProtocolStore aliceStore, SignalProtocolStore bobStore) {
	    return Arrays.equals(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getAliceBaseKey(),
	                         bobStore.loadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey());
	  }

	  private PreKeyBundle createAlicePreKeyBundle(SignalProtocolStore aliceStore) throws InvalidKeyException {
	    ECKeyPair aliceUnsignedPreKey   = Curve.generateKeyPair();
	    int       aliceUnsignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
	    byte[]    aliceSignature        = Curve.calculateSignature(aliceStore.getIdentityKeyPair().getPrivateKey(),
	                                                               aliceSignedPreKey.getPublicKey().serialize());

	    PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
	                                                      aliceUnsignedPreKeyId, aliceUnsignedPreKey.getPublicKey(),
	                                                      aliceSignedPreKeyId, aliceSignedPreKey.getPublicKey(),
	                                                      aliceSignature, aliceStore.getIdentityKeyPair().getPublicKey());

	    aliceStore.storeSignedPreKey(aliceSignedPreKeyId, new SignedPreKeyRecord(aliceSignedPreKeyId, System.currentTimeMillis(), aliceSignedPreKey, aliceSignature));
	    aliceStore.storePreKey(aliceUnsignedPreKeyId, new PreKeyRecord(aliceUnsignedPreKeyId, aliceUnsignedPreKey));

	    return alicePreKeyBundle;
	  }

	  private PreKeyBundle createBobPreKeyBundle(SignalProtocolStore bobStore) throws InvalidKeyException {
	    ECKeyPair bobUnsignedPreKey   = Curve.generateKeyPair();
	    int       bobUnsignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
	    byte[]    bobSignature        = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
	                                                             bobSignedPreKey.getPublicKey().serialize());

	    PreKeyBundle bobPreKeyBundle = new PreKeyBundle(1, 1,
	                                                    bobUnsignedPreKeyId, bobUnsignedPreKey.getPublicKey(),
	                                                    bobSignedPreKeyId, bobSignedPreKey.getPublicKey(),
	                                                    bobSignature, bobStore.getIdentityKeyPair().getPublicKey());

	    bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId, System.currentTimeMillis(), bobSignedPreKey, bobSignature));
	    bobStore.storePreKey(bobUnsignedPreKeyId, new PreKeyRecord(bobUnsignedPreKeyId, bobUnsignedPreKey));

	    return bobPreKeyBundle;
	  }
	  
	  
	  public static void main(String[] args) {
		SimultaneousInitiateTests tests = new SimultaneousInitiateTests();
		  
		  try {
			tests.testBasicSimultaneousInitiate();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UntrustedIdentityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidVersionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidMessageException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DuplicateMessageException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (LegacyMessageException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyIdException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSessionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
