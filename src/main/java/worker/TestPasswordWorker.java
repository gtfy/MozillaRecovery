package worker;

import java.io.IOException;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

import model.Key3DBParseException;
import model.Key3DBParser;
import delegate.MainFrame;
import delegate.ProgressDisplay;

public class TestPasswordWorker extends Thread{
	private final static Logger logger = Logger.getLogger(TestPasswordWorker.class);
	
	private ArrayBlockingQueue<byte[]> jobQueue;
	private ProgressDisplay progressDisplay;
	private final Key3DBParser parser;
	private boolean isShutdown;
	
	public TestPasswordWorker(String key3Path, ArrayBlockingQueue<byte[]> jobQueue, ProgressDisplay progressDisplay) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, Key3DBParseException {
		this.jobQueue = jobQueue;
		this.progressDisplay = progressDisplay;
		this.parser = new Key3DBParser(key3Path);
		this.isShutdown = false;
		
		// TODO: check if parsing was successful
		parser.parse();
	}
	
	
	
	
	public synchronized void shutdownWhenEmpty(){
		isShutdown = true;
	}
	
	@Override
	public void run() {
		int maxElements = 100000;
		byte[] first;
		List<byte[]> tmpWords = new ArrayList<byte[]>(maxElements);
		int i;
		
		// test if the pass is empty

			try {
				if(parser.isMasterpass("".getBytes())){
					progressDisplay.workerDone(this);
					progressDisplay.setResult("");
					return;
				}
			} catch (InvalidKeyException | InvalidKeySpecException
					| InvalidAlgorithmParameterException
					| IllegalBlockSizeException | BadPaddingException
					| DigestException | ShortBufferException | IllegalStateException e1) {
				e1.printStackTrace();
			}

		
		while(! interrupted()){
			if(isShutdown && jobQueue.isEmpty()){
				break;
			}
			
			try {
				first = jobQueue.poll(5, TimeUnit.SECONDS);
				if(first == null) continue;
			} catch (InterruptedException e) {
				break;
			}
			jobQueue.drainTo(tmpWords, maxElements);
			tmpWords.add(first);
			// shouldn't cost to much performance if buffer size is large enough
			logger.debug("Worker " + getName() + " got " + tmpWords.size() + " words");
			
			for (i = 0; i < tmpWords.size(); i++) {
				try {
					if(parser.isMasterpass(tmpWords.get(i))){
						System.out.println("Password found: " + new String(tmpWords.get(i)));
						progressDisplay.addProgress(i+1, "");
						progressDisplay.workerDone(this);
						progressDisplay.setResult(new String(tmpWords.get(i)));
						return;
					}
				} catch (InvalidKeyException | InvalidKeySpecException
						| InvalidAlgorithmParameterException
						| IllegalBlockSizeException | BadPaddingException | DigestException | ShortBufferException | IllegalStateException e) {
					// TODO All of these should be critical error, i guess ?
					// TODO think about it. 
					e.printStackTrace();
				}
			}
			if(interrupted()) break;
			progressDisplay.addProgress(i, new String(tmpWords.get(tmpWords.size()-1)) );
			tmpWords.clear();
		}
		progressDisplay.workerDone(this);
	}
	
}
