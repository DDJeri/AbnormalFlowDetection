package Process_module;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import Tool_module.HashUtil;

public class BF {
	
	private int length = 16;
	private boolean[] BloomFilter = new boolean[(int)Math.pow(2,length)];
	private String[] Hash = new String[]{"MD5","SHA1"};
	private int[] CommonPortNumber = {137,80,8080,3128,8081,9080,1080,21,23,443,69,22,25,110,7001,9090,3389,1521,1158,2100,1433};
	public Map<String,Integer> StatisticsCount = new HashMap<String,Integer>();
	
	public void BloomInsert(String a) {    //特征+宿端口号
		int hashresult[] = new int[Hash.length];
		for(int i=0;i<Hash.length;i++) {
			String t = HashUtil.hash(a, Hash[i]);
			hashresult[i] = Integer.parseInt(t.substring(0, length/4),16);
			BloomFilter[hashresult[i]] = true; 
		}
		
	}
	
	public void Statistics(ArrayList<String> StatisticsPackages,double p) {
		for(int i=0;i<StatisticsPackages.size();i++) {
			int num = 0;
			for(int j=0;j<CommonPortNumber.length;j++) {
				String t = StatisticsPackages.get(i)+","+CommonPortNumber[j];
				if(BloomInquery(t)) num++;
			}
			StatisticsCount.put(StatisticsPackages.get(i),num);
		}
	}
	
	public boolean BloomInquery(String a) { //存在是true
		int hashresult[] = new int[Hash.length];
		for(int i=0;i<Hash.length;i++) {
			String t = HashUtil.hash(a, Hash[i]);
			hashresult[i] = Integer.parseInt(t.substring(0, length/4),16);
		}
		boolean flag = true;
		for(int i=0;i<hashresult.length;i++) 
			if(!BloomFilter[hashresult[i]]) {flag = false;break;}
		return flag;
	}
	
}
