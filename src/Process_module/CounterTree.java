package Process_module;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

import Tool_module.HashUtil;
import Tool_module.StringMove;

public class CounterTree {
	
	private int m=256,d=2,h=9,r=100,n=0,b=3 ;  //n报文总数量
	private int allNodes = (int)((Math.pow(d, h)-1)/(d-1));
	private byte[] counterTree = new byte[allNodes+1];
	private int Move[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	private String XOR[] = new String[r];
	public Map<String,Integer> StatisticsCount = new HashMap<String,Integer>();
	
	private int bfs(int root,int p) {
		Queue<Integer> queue = new LinkedList<Integer>();
		queue.add(root);queue.add(p);
		
		int i,j,x=0;
		while(!queue.isEmpty()) {
			i = queue.poll();
			j = queue.poll();
			x += counterTree[i]*(int)Math.pow(2, j);
			if(i*2 <= allNodes) {
				queue.add(i*2);queue.add(j-b);
				queue.add(i*2+1);queue.add(j-b);
			}
		}
		return x;
	}
	
	private int effecitve_H_cal() {
		int i=1;
		for(int j=1;;j++) {
			for(int t=0;t<(int)(Math.pow(2, j-1));t++) {
				if(counterTree[i+t] > 0)
					return h-j+1;
			}
			i+=(int)(Math.pow(2, j-1));
		}
	}
	
	public CounterTree() {
		for(int i=0;i<counterTree.length;i++)
			counterTree[i] = 0;
		String id = String.format("%01d", 1);
		char[] cs = id.toCharArray(); //获取对应的字符数组
		for(int i=0;i<XOR.length;i++) {
			cs[0] += 1;
			XOR[i] = new String(cs);
		}
	}
	
	public void Count(String a) {
		int i = (int)Math.floor(Math.random()*r);   //随机选择hash函数
		String t1 = StringMove.hash_xor(a, XOR[i]);
		String t = HashUtil.hash(t1, "MD5");
		int hashresult = Integer.parseInt(t.substring(0, 4),16);
		
		i = hashresult%m + (allNodes-m+1); //选中的叶子节点编号
		
		//开始增加
		while(i != 0) {
			if(counterTree[i] == (int)Math.pow(2, b)-1) {
				counterTree[i] = 0;
				i = i/2;
			}else {
				counterTree[i]++;
				i = 0;
			}
		}
		n++;
	}
	
	public void Statistics(ArrayList<String> StatisticsPackages,double p) {
		int effective_h = effecitve_H_cal();
		System.out.println("n:"+n+"   h':"+effective_h);
		int a,k=(int)Math.pow(2, effective_h-1),x=0; 
		
		for(int i=0;i<StatisticsPackages.size();i++) {
			x = 0;
			for(int j=0;j<r;j++) {
				String t = HashUtil.hash(StringMove.hash_xor(StatisticsPackages.get(i),XOR[j]), "MD5");
				int hashresult = Integer.parseInt(t.substring(0, 4),16);
				a = hashresult%m + (allNodes-m+1); //选中的叶子节点编号
				
				//计算x
				for(int w=0;w<effective_h-1;w++) a/=2;
				x += bfs(a, (effective_h-1)*b);
			}
			StatisticsCount.put(StatisticsPackages.get(i),x-(int)(n*k*r/m)+(int)(1/p)-1);
		}
	}
	
}
