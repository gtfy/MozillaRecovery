package worker;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.channels.ClosedByInterruptException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.ArrayBlockingQueue;

import delegate.ProgressDisplay;

public class WordListWorker extends Thread {
	private ArrayBlockingQueue<byte[]> queue;
	private ProgressDisplay progress;
	private BufferedReader reader;
	private String wordlist;
	
	public WordListWorker(String wordlistPath, ProgressDisplay progress, ArrayBlockingQueue<byte[]> queue) throws IOException {
		// TODO test if the file is readable
		this.reader = Files.newBufferedReader(new File(wordlistPath).toPath(), StandardCharsets.ISO_8859_1);
		this.wordlist = wordlistPath;		
		this.queue = queue;
		this.progress = progress;
	}
	public WordListWorker(InputStream inputStream, ProgressDisplay progress, ArrayBlockingQueue<byte[]> queue) throws IOException {
		// TODO think about charset ? it get utf-8- encoded anyway ?
		// TODO test if the inputStream is open
		this.reader = new BufferedReader(new InputStreamReader(inputStream));
		this.wordlist = inputStream.toString();	// or user hard coded string ?	
		this.queue = queue;
		this.progress = progress;
	}	
	
	
	@Override
	public void run() {
		String data = null;
		Charset utf8_cs = Charset.forName("UTF-8");
		int batchSize = 100000;
		int maxWordLength = 512; // the internal buffer is 2048, so why not ?
		int i = 0;
		try {
			while(! interrupted()){
				for (i = 0; i < batchSize && (data = reader.readLine()) != null; ++i) {
					if(data.length() > maxWordLength){
						System.out.println("skip");
						i--;
						continue;
					}
					//System.out.println(data);
					queue.put( utf8_cs.encode(data).array() );	
				}
				if(data == null)break;
			}
		} catch (InterruptedException e) {
			// nothing to see, move along
//			e.printStackTrace();
		} catch (ClosedByInterruptException e) {
			// nothing to see, move along
//			e.printStackTrace();
		} catch (IOException e1) {
			//TODO ... Could happen if the file got removed during read or some fuckery i guess.
			// What to do ? Notify the proggressManager or just die silently ?
			//e1.printStackTrace(); // TODO log this
		}
		finally{
			try{ reader.close(); }
			catch (IOException e){}
		}
		progress.producerDone(this);
	}
}
