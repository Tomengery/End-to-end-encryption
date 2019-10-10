package main.code;

import java.util.*;
import java.io.*;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.MessageListener;
import org.jivesoftware.smack.Roster;
import org.jivesoftware.smack.RosterEntry;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.Chat;
import static org.whispersystems.curve25519.Curve25519.BEST;

/*import java.util.Base64;
import java.util.List;
import java.util.Random;*/

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

public class Testing implements MessageListener {
	XMPPConnection connection;

	static ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();
	static IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
			aliceIdentityKeyPair.getPrivateKey());
	static ECKeyPair aliceBaseKey = Curve.generateKeyPair();
	ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

	ECKeyPair alicePreKey = aliceBaseKey;

	static ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
	static IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
			bobIdentityKeyPair.getPrivateKey());
	static ECKeyPair bobBaseKey = Curve.generateKeyPair();
	static ECKeyPair bobEphemeralKey = bobBaseKey;

	ECKeyPair bobPreKey = Curve.generateKeyPair();

	public void login(String userName, String password) throws XMPPException {
		ConnectionConfiguration config = new ConnectionConfiguration("report.pune.cdac.in");
		// config.setDebuggerEnabled(true);;
		connection = new XMPPConnection(config);
		// XMPPConnection.DEBUG_ENABLED = true;

		connection.connect();
		System.out.println("Conection Established");
		connection.login(userName, password);
	}

	public void sendMessage(String message, String to) throws XMPPException 
	{
		
		Chat chat = connection.getChatManager().createChat(to, this);
		chat.sendMessage(message);
		System.out.println("Manual checking");
	}

	public void disconnect() {
		connection.disconnect();
	}

	@Override
	public void processMessage(Chat chat, Message message) {

		if (message.getType() == Message.Type.chat)
			System.out.println(chat.getParticipant() + " says: " + message.getBody());
	}

	public static void main(String[] args) throws XMPPException, IOException {
		try {

			Testing c = new Testing();
			// InputStreamReader x = new InputStreamReader(System.in);
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			String msg;

			// turn on the enhanced debugger
			XMPPConnection.DEBUG_ENABLED = true;
			// setDebuggerEnabled(true);

			// Enter your login information here
			c.login("user1@report.pune.cdac.in", "password1");
			System.out.println("Welcome");

			System.out.println("Enter the user name:");
			String talkTo = br.readLine();

			System.out.println("-----");
			System.out.println("All messages will be sent to " + talkTo);
			System.out.println("Enter your message:");
			System.out.println("-----\n");

			msg = br.readLine();

			SessionRecord aliceSessionRecord = new SessionRecord();
			AliceSignalProtocolParameters aliceParameters = AliceSignalProtocolParameters.newBuilder()
					.setOurBaseKey(aliceBaseKey).setOurIdentityKey(aliceIdentityKey)
					.setTheirOneTimePreKey(Optional.<ECPublicKey>absent())
					.setTheirRatchetKey(bobEphemeralKey.getPublicKey()).setTheirSignedPreKey(bobBaseKey.getPublicKey())
					.setTheirIdentityKey(bobIdentityKey.getPublicKey()).create();
			RatchetingSession.initializeSession(aliceSessionRecord.getSessionState(), aliceParameters);

			SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
			aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
			SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));

			SessionRecord bobSessionRecord = new SessionRecord();
			BobSignalProtocolParameters bobParameters = BobSignalProtocolParameters.newBuilder()
					.setOurRatchetKey(bobEphemeralKey).setOurSignedPreKey(bobBaseKey)
					.setOurOneTimePreKey(Optional.<ECKeyPair>absent()).setOurIdentityKey(bobIdentityKey)
					.setTheirIdentityKey(aliceIdentityKey.getPublicKey()).setTheirBaseKey(aliceBaseKey.getPublicKey())
					.create();

			RatchetingSession.initializeSession(bobSessionRecord.getSessionState(), bobParameters);

			SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();
			bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);
			SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));
			byte[] alicePlaintext = msg.getBytes();// "This is a plaintext message.".getBytes();
			byte[] alicePlaintext2 = "This is a plaintext message 2.".getBytes();
			byte[] alicePlaintext3 = "This is a plaintext message 3.".getBytes();
			byte[] alicePlaintext4 = "This is a plaintext message 4.".getBytes();
			byte[] alicePlaintext5 = "This is a plaintext message 5.".getBytes();
			byte[] alicePlaintext6 = "This is a plaintext message 6.".getBytes();
			byte[] alicePlaintext7 = "This is a plaintext message 7.".getBytes();
			byte[] alicePlaintext8 = "This is a plaintext message 8.".getBytes();
			byte[] alicePlaintext9 = "This is a plaintext message 9.".getBytes();

			byte[] bobPlaintext = "BOB This is a plaintext message.".getBytes();
			byte[] bobPlaintext2 = "BOB This is a plaintext message 2.".getBytes();
			byte[] bobPlaintext3 = "This is a plaintext message 3.".getBytes();

			CiphertextMessage alicemessage = aliceCipher.encrypt(alicePlaintext);
			String y = new String(alicemessage.serialize());
			System.out.println(y.getClass().getSimpleName());
			byte[] bob1 = bobCipher.decrypt(new SignalMessage(alicemessage.serialize()));
			// System.out.println(new String(bob1));
			System.out.println(y);
			//String z = new String(bob1);
			//c.sendMessage(new String(bob1), talkTo);
			c.sendMessage(y, talkTo);

			CiphertextMessage alicemessage2 = aliceCipher.encrypt(alicePlaintext2);
			CiphertextMessage alicemessage3 = aliceCipher.encrypt(alicePlaintext2);
			CiphertextMessage alicemessage4 = aliceCipher.encrypt(alicePlaintext2);
			CiphertextMessage alicemessage7 = aliceCipher.encrypt(alicePlaintext2);
			CiphertextMessage alicemessage8 = aliceCipher.encrypt(alicePlaintext2);
			CiphertextMessage alicemessage9 = aliceCipher.encrypt(alicePlaintext2);

			CiphertextMessage bobmessage = bobCipher.encrypt(bobPlaintext);
			// System.out.println(new SignalMessage(bobmessage.serialize()));
			byte[] alice = aliceCipher.decrypt(new SignalMessage(bobmessage.serialize()));
			System.out.println("---------------------------------------\n\n\n\n\n");
			
			  System.out.println(new String(alice));
			  
			  CiphertextMessage alicemessage5 = aliceCipher.encrypt(alicePlaintext4);
			  byte[] bob4 = bobCipher.decrypt(new
			  SignalMessage(alicemessage5.serialize())); System.out.println(new
			  String(bob4));
			  
			  CiphertextMessage bobmessage2 = bobCipher.encrypt(bobPlaintext2); byte[]
			  alice2 = aliceCipher.decrypt(new SignalMessage(bobmessage2.serialize()));
			  System.out.println(new String(alice2));
			  
			  
			/*
			 * CiphertextMessage alicemessage5 = aliceCipher.encrypt(alicePlaintext5);
			 * CiphertextMessage alicemessage6 = aliceCipher.encrypt(alicePlaintext6);
			 */
			  
			  byte[] bob8 = bobCipher.decrypt(new
			  SignalMessage(alicemessage9.serialize())); System.out.println(new
			  String(bob8));
			  
			  byte[] bob2 = bobCipher.decrypt(new
			  SignalMessage(alicemessage2.serialize())); System.out.println(new
			  String(bob2)); byte[] bob3 = bobCipher.decrypt(new
			  SignalMessage(alicemessage3.serialize())); System.out.println(new
			  String(bob2));
			  
			  byte[] bob5 = bobCipher.decrypt(new
			  SignalMessage(alicemessage4.serialize())); System.out.println(new
			  String(bob5));
			  
			  byte[] bob6 = bobCipher.decrypt(new
			  SignalMessage(alicemessage7.serialize())); System.out.println(new
			  String(bob6)); byte[] bob7 = bobCipher.decrypt(new
			  SignalMessage(alicemessage8.serialize())); System.out.println(new
			  String(bob7));
			 
			
			//  while( (msg=br.readLine()).equals("bye")) { c.sendMessage(msg, talkTo); 
			 
//		if(msg=br.readLine().equals("bye"))

			c.disconnect();
			System.exit(0);
			//  }
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

