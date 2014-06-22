package worker;

public abstract class PasswordWorkerInterface extends Thread {
	public abstract void shutdownWhenEmpty();
}
