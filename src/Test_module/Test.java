package Test_module;

import java.io.File;
import java.util.ArrayList;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import Process_module.*;
import Tool_module.HashUtil;
import pcapAnalyzer.pcapParse;

public class Test {
	public static void main(String[] args) {
		
		
		String inputFile = "C:/Users/ddd/Desktop/test.pcap",outFile = "C:/Users/ddd/Desktop/test.txt";
		File f1 = new File(inputFile);
		File f2 = new File(outFile);
		pcapParse pcap = new pcapParse(f1,f2);
		System.out.println(pcap.parse());   //解析
		
		ArrayList<String> packages = pcap.simplified_packages;
		for(int i=0;i<packages.size();i++) {
			String t=packages.get(i);
			System.out.println(t);
		}
		/*
		Filter FilterModule = new Filter(0.5);
		CBF CBFModule = new CBF();
		CounterTree CTModule = new CounterTree();
		for(int i=0;i<packages.size();i++) {     //过滤和计数
			if(FilterModule.BloomJudge(packages.get(i))) {
				CBFModule.Count(packages.get(i));
				CTModule.Count(packages.get(i));
			}
		}
		CBFModule.Statistics(FilterModule.Statistics, FilterModule.SamplingProbability); //统计
		CTModule.Statistics(FilterModule.Statistics, FilterModule.SamplingProbability); //统计
		
		//对比
		Map<String,Integer> a = CBFModule.StatisticsCount;
		Map<String,Integer> b = CTModule.StatisticsCount;
		
		for(int i=0;i<pcap.limit_packages.size();i++) {
			String t=pcap.limit_packages.get(i);
			System.out.println(t + ": " + a.get(t) + " " + b.get(t));
		}
		*/
		
	}
}
