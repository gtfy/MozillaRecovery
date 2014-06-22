package delegate;

import worker.PasswordWorkerInterface;

public interface ProgressDisplay {
	public void addProgress(int size, String currentTry);

	public void setResult(String password);

	
	public void workerDone(PasswordWorkerInterface name);
	public void producerDone(Thread name);
}
