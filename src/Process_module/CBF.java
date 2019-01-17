package Process_module;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import Tool_module.HashUtil;

public class CBF {
	
	private int length = 8;
	private int[] CountBloomFilter = new int[(int)Math.pow(2,length)];
	private String[] Hash = new String[]{"MD5","SHA1"};
	public Map<String,Integer> StatisticsCount = new HashMap<String,Integer>();
	
	public void Count(String a) {
		for(int i=0;i<Hash.length;i++) {
			String t = HashUtil.hash(a, Hash[i]);
			int hashresult = Integer.parseInt(t.substring(0, length/4),16);
			CountBloomFilter[hashresult]++;
		}
	}
	
	public void Statistics(ArrayList<String> StatisticsPackages,double p) {
		for(int i=0;i<StatisticsPackages.size();i++) {
			int smin = Integer.MAX_VALUE;
			for(int j=0;j<Hash.length;j++) {
				String t = HashUtil.hash(StatisticsPackages.get(i), Hash[j]);
				int hashresult = Integer.parseInt(t.substring(0, length/4),16);
				if(CountBloomFilter[hashresult] < smin) {
					smin = CountBloomFilter[hashresult];
				}
			}
			StatisticsCount.put(StatisticsPackages.get(i),smin);
		}
	}
}
