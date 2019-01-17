package Tool_module;

public class StringMove {
	//返回左移n位字符串方法	
	public static String moveToLeft(String str,int position) {		
		String str1=str.substring(position);		
		String str2=str.substring(0, position);		
		return str1+str2;	
	}	
	
	//返回右移n位字符串方法		
	public static String moveToRight(String str,int position) {
		String str1=str.substring(str.length()-position);			
		String str2=str.substring(0, str.length()-position);			
		return str1+str2;		
	}
	
	public static String hash_xor(String x,String y) {
		
		String t = "";
		for(int i=0;i<20;i++)
			t += xor(x.substring(i, i+1), y);
		return t+x.substring(x.length()-10);
	}

	public static String xor(String strHex_X,String strHex_Y){ 
			//将x、y转成二进制形式 
			char A[] = strHex_X.toCharArray();
			char B[] = strHex_Y.toCharArray();
			String anotherBinary=Integer.toBinaryString(A[0]); 
			String thisBinary=Integer.toBinaryString(B[0]); 
			String result = ""; 

			//判断是否为8位二进制，否则左补零 			
			if(anotherBinary.length() != 8){ 			
				for (int i = anotherBinary.length(); i <8; i++) { 					
					anotherBinary = "0"+anotherBinary; 				
				} 			
			} 			
			if(thisBinary.length() != 8){
				for (int i = thisBinary.length(); i <8; i++) { 	
					thisBinary = "0"+thisBinary; 				
					} 			
			} 
			
			//异或运算 
			for(int i=0;i<anotherBinary.length();i++){ 
			//如果相同位置数相同，则补0，否则补1 
				if(thisBinary.charAt(i)==anotherBinary.charAt(i)) 
					result+="0"; 
				else{ 
					result+="1"; 
				} 
			}
			return Integer.toHexString(Integer.parseInt(result, 2)); 
		}
}
