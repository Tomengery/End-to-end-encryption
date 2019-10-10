import java.util.List;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore.Direction;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemoryIdentityKeyStore;
import org.whispersystems.libsignal.state.impl.InMemoryPreKeyStore;
import org.whispersystems.libsignal.state.impl.InMemorySessionStore;
import org.whispersystems.libsignal.state.impl.InMemorySignedPreKeyStore;
import org.whispersystems.libsignal.util.KeyHelper;

public class InMemoryAxolotlStore {
	int                ourRegistrationId  = KeyHelper.generateRegistrationId(true);
	public int getOurRegistrationId() {
		return ourRegistrationId;
	}


	public void setOurRegistrationId(int ourRegistrationId) {
		this.ourRegistrationId = ourRegistrationId;
	}


	private final InMemoryIdentityKeyStore  identityKeyStore  = new InMemoryIdentityKeyStore(KeyHelper.generateIdentityKeyPair(),ourRegistrationId);
	  private final InMemoryPreKeyStore       preKeyStore       = new InMemoryPreKeyStore();
	  private final InMemorySessionStore      sessionStore      = new InMemorySessionStore();
	  private final InMemorySignedPreKeyStore signedPreKeyStore = new InMemorySignedPreKeyStore();


	 
	  public IdentityKeyPair getIdentityKeyPair() {
	    return identityKeyStore.getIdentityKeyPair();
	  }

	  
	  public int getLocalRegistrationId() {
	    return identityKeyStore.getLocalRegistrationId();
	  }

	
	  public void saveIdentity(SignalProtocolAddress address,IdentityKey identityKey) {
	    identityKeyStore.saveIdentity(address,identityKey);
	  }

	 
	  public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey ,Direction direction) {
	    return identityKeyStore.isTrustedIdentity(address, identityKey, direction);
	  }

	  
	  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
	    return preKeyStore.loadPreKey(preKeyId);
	  }

	 
	  public void storePreKey(int preKeyId, PreKeyRecord record) {
	    preKeyStore.storePreKey(preKeyId, record);
	  }

	  
	  public boolean containsPreKey(int preKeyId) {
	    return preKeyStore.containsPreKey(preKeyId);
	  }

	  
	  public void removePreKey(int preKeyId) {
	    preKeyStore.removePreKey(preKeyId);
	  }

	  
	  public SessionRecord loadSession(SignalProtocolAddress address) {
	    return sessionStore.loadSession(address);
	  }

	  
	  public List<Integer> getSubDeviceSessions(String name) {
	    return sessionStore.getSubDeviceSessions(name);
	  }

	  
	  public void storeSession(SignalProtocolAddress address, SessionRecord record) {
	    sessionStore.storeSession(address,record);
	  }

	  
	  public boolean containsSession(SignalProtocolAddress address) {
	    return sessionStore.containsSession(address);
	  }

	  
	  public void deleteSession(SignalProtocolAddress address) {
	    sessionStore.deleteSession(address);
	  }

	  
	  public void deleteAllSessions(String recipientId) {
	    sessionStore.deleteAllSessions(recipientId);
	  }

	  
	  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
	    return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
	  }

	  
	  public List<SignedPreKeyRecord> loadSignedPreKeys() {
	    return signedPreKeyStore.loadSignedPreKeys();
	  }

	  
	  public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
	    signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
	  }

	  
	  public boolean containsSignedPreKey(int signedPreKeyId) {
	    return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
	  }

	  
	  public void removeSignedPreKey(int signedPreKeyId) {
	    signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
	  }
}
