package Process_module;

import java.util.ArrayList;

public class portScan {
	
	private Filter filter = new Filter(1);
	private CBF cbf = new CBF();
	private CBF cbfsyn = new CBF();
	ArrayList<String> packs,packages;
	
	public void portScan(ArrayList<String> packages) {
		for(int i=0;i<packages.size();i++) {
			String subSentences[] = packages.get(i).split(",");
			packs.add(subSentences[0]+","+subSentences[1]);
		}
		this.packages = packages;
	}
	
	public void process() {
		for(int i=0;i<packs.size();i++) {
			if(filter.BloomJudge(packs.get(i))) {
				cbf.Count(packs.get(i));
				String subSentences[] = packages.get(i).split(",");
				if(subSentences[3] == "0") {
					cbfsyn.Count(packs.get(i));
				}
			}
		}
	}
	
}
