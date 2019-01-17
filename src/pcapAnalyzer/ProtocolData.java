package pcapAnalyzer;

/**
 * 协议数据，三元组
 * @author johnnie
 *
 */
public class ProtocolData {

	String srcIP;										// 源 IP
	String desIP;										// 目的 IP
	
	int srcPort;										// 源端口
	int desPort;										// 目的端口
	
	short dateLength;										// data长度
	
	byte protocolType;		// 协议类型

	public String getSrcIP() {
		return srcIP;
	}

	public void setSrcIP(String srcIP) {
		this.srcIP = srcIP;
	}

	public String getDesIP() {
		return desIP;
	}

	public void setDesIP(String desIP) {
		this.desIP = desIP;
	}
	
	
	public int getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(int srcPort) {
		this.srcPort = srcPort;
	}

	public int getDesPort() {
		return desPort;
	}

	public void setDesPort(int desPort) {
		this.desPort = desPort;
	}
	
	public short getDateLength() {
		return dateLength;
	}

	public void setDateLength(short dateLength) {
		this.dateLength = dateLength;
	}
	

	public byte getProtocolType() {
		return protocolType;
	}

	public void setProtocolType(byte protocolType) {
		this.protocolType = protocolType;
	}

	public ProtocolData() {
		// TODO Auto-generated constructor stub
	}

	public ProtocolData(String srcIP, String desIP, 
			 byte protocolType) {
		this.srcIP = srcIP;
		this.desIP = desIP;
		//this.srcPort = srcPort;
		//this.desPort = desPort;
		this.protocolType = protocolType;
	}

	@Override
	public String toString() {
		return  srcIP
				+ "," + desIP
				+ "," + protocolType
				+ "," + dateLength
				+ "," + srcPort
				+ "," + desPort;
	}

}
