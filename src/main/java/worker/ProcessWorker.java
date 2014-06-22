package worker;

import java.io.IOException;
import java.util.concurrent.ArrayBlockingQueue;

import delegate.ProgressDisplay;

public class ProcessWorker extends WordListWorker{

	private final Process process;

	public ProcessWorker(Process process, ProgressDisplay progress, ArrayBlockingQueue<byte[]> queue) throws IOException {
		super(process.getInputStream(), progress, queue);
		this.process = process;		
	}

	@Override
	public void interrupt() {
		process.destroy();
		super.interrupt();
	}

	@Override
	public void run() {
		super.run();
		try {
			process.waitFor();
		} catch (InterruptedException e) {
		}
	}
}
