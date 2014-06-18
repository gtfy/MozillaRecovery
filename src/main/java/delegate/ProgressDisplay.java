package delegate;

import worker.TestPasswordWorker;

public interface ProgressDisplay {
	public void addProgress(int size, String currentTry);

	public void setResult(String password);

	
	public void workerDone(TestPasswordWorker name);
	public void producerDone(Thread name);
}
