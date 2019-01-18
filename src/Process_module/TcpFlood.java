package Process_module;

import java.util.ArrayList;

public class TcpFlood {
	private Filter filter;
	private CBF cbf;
	private CBF cbfsyn;
	ArrayList<String> packs;
	
	public TcpFlood(ArrayList<String> packages) {
		
		filter = new Filter(1);
		cbf = new CBF();
		cbfsyn = new CBF();
		packs = new ArrayList<String>();
		
		for(int i=0;i<packages.size();i++) {
			String subSentences[] = packages.get(i).split(",");
			packs.add(subSentences[1]+","+subSentences[5]+","+subSentences[6]);   //宿地址和宿端口
		}
		process();
	}
	
	private void process() {
		for(int i=0;i<packs.size();i++) {
			String subSentences[] = packs.get(i).split(",");
			String t = subSentences[0]+","+subSentences[1];
			if(filter.BloomJudge(t)) {
				cbf.Count(t);
				if(subSentences[2].equals("true")) {     //是不是syn或者fin
					cbfsyn.Count(t);
				}
			}
		}
	}
	
	public void show() {
		cbf.Statistics(filter.Statistics, 1);
		cbfsyn.Statistics(filter.Statistics, 1);
		System.out.println("\r\nTCP洪泛扫描结果");
		for(int i=0;i<filter.Statistics.size();i++) {
			String t = filter.Statistics.get(i);
			if(cbf.StatisticsCount.get(t) > 200)
				System.out.println(cbf.StatisticsCount.get(t) + "  " + cbfsyn.StatisticsCount.get(t));
		}
	}
}
