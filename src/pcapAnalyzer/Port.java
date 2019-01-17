package pcapAnalyzer;

public class Port {
	private short srcport;
	private short dstport;
	
	public short getsrcport() {
		return srcport;
	}

	public void setsrcport(short srcport) {
		this.srcport = srcport;
	}
	
	public short getdstport() {
		return dstport;
	}

	public void setdstport(short dstport) {
		this.dstport = dstport;
	}
	
	public Port() {srcport = 0;dstport = 0;	}
}
