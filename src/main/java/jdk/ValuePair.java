package jdk;

import java.util.ArrayList;
import java.util.List;

import org.apache.http.message.BasicNameValuePair;
import org.omg.CORBA.NameValuePair;


public class ValuePair  {
	
	
	public void getInfo(){
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        nvps.add(new NameValuePair());
		MacManage name = new MacManage(){

			public String operate(int type) {
				type++;
				return null;
			}
			
		};
		
	}

 

}
