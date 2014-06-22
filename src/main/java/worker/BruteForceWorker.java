package worker;

import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;

import delegate.ProgressDisplay;

// TODO derivate for processWorker. overwrite interupt(kill) and run(join)
public class BruteForceWorker extends Thread {

	private int maxWordLength;
	private char[] chars;
	private ArrayBlockingQueue<byte[]> queue;
	private ProgressDisplay progress;

	public BruteForceWorker(char chars[], int maxWordLength, ProgressDisplay progress, ArrayBlockingQueue<byte[]> queue) {
		this.chars = chars;
		this.maxWordLength = maxWordLength;
		this.queue = queue;
		this.progress = progress;
	}
	
	
	@Override
	public void run() {
		char firstChar = chars[0];
		int idata[] = new int[]{0};
		int maxChar = chars.length-1;
		int curLen = 1; 
		
		Charset utf8_cs = Charset.forName("UTF-8");
		CharBuffer buff = CharBuffer.wrap(new char[]{chars[0]});
			
		int pos = 0;
		try {
			while(! interrupted()){
				buff.position(0);
					// TODO buffer and use addAll to minimize locking overhead ?
					queue.put( utf8_cs.encode(buff).array() );
				// 
				for (pos = 0; pos < curLen && idata[pos] == maxChar ; idata[pos] = 0, buff.put(pos, firstChar), pos++);
				if(pos != curLen){
					idata[pos] += 1;
					buff.put(pos, chars[idata[pos]]);
				}else{
					if(curLen != maxWordLength){
						curLen += 1;
						idata = Arrays.copyOf(idata, curLen);
						buff = CharBuffer.allocate(curLen);
						for (int i = 0; i < curLen; buff.put(i, firstChar), i++);
					}else{					
						break;
					}
				}
			}
		} catch (InterruptedException e) {
			// meh
		}
		progress.producerDone(this);
	}
}
