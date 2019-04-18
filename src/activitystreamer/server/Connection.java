package activitystreamer.server;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import activitystreamer.util.Settings;

public class Connection extends Thread {
	private static final Logger log = LogManager.getLogger();
	private DataInputStream in;
	private DataOutputStream out;
	private BufferedReader inreader;
	private PrintWriter outwriter;
	private boolean open = false;
	private Socket socket;
	private boolean term=false;

	//Each connection has a username-secret pair to identify itself.
	private String username = Settings.getUsername();
	//Default secret, it can be any except null.
	private String secret = "burger";
	private boolean isLogin = false;
	//The number of LOCK_ALLOWED the client connection should be received to successfully register
	private int numOfAllow;

	
	Connection(Socket socket) throws IOException{
		in = new DataInputStream(socket.getInputStream());
	    out = new DataOutputStream(socket.getOutputStream());
	    inreader = new BufferedReader( new InputStreamReader(in));
	    outwriter = new PrintWriter(out, true);
	    this.socket = socket;
	    open = true;
	    start();
	}
	
	/*
	 * returns true if the message was written, otherwise false
	 */
	public boolean writeMsg(String msg) {
		if(open){
			outwriter.println(msg);
			outwriter.flush();
			return true;	
		}
		return false;
	}
	
	public void closeCon(){
		if(open){
			log.info("closing connection " + Settings.socketAddress(socket));
			try {
				term=true;
				inreader.close();
				out.close();
			} catch (IOException e) {
				// already closed?
				log.error("received exception closing the connection " + Settings.socketAddress(socket) + ": " + e);
			}
		}
	}
	
	
	public void run(){
		try {
			String data;
			while (!term && (data = inreader.readLine()) != null) {
				term = Control.getInstance().process(this, data);
			}
		
			log.debug("connection closed to " + Settings.socketAddress(socket));
			if (secret.equals(Settings.getSecret())) {
				//System.out.println("delete!!!!!");
			    Map<String, String[]> newServerTable = Control.getInstance().getServerTable();
			    newServerTable.remove(username);
			    Control.getInstance().setServerTable(newServerTable);
			}
			
			Control.getInstance().connectionClosed(this);
			in.close();	
		} catch (SocketException e1) {
			log.debug("connection closed to " + Settings.socketAddress(socket));
			Control.getInstance().connectionClosed(this);
			try {
				in.close();
				out.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
		} catch (SocketTimeoutException e2) {
			log.debug("connection closed to " + Settings.socketAddress(socket));
			Control.getInstance().connectionClosed(this);
			try {
				in.close();
				out.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		} catch (IOException e) {
			log.error("connection " + Settings.socketAddress(socket) + " closed with exception: " + e);
			Control.getInstance().connectionClosed(this);
		}

		open = false;
	}
	
	public Socket getSocket() {
		return socket;
	}
	
	public boolean isOpen() {
		return open;
	}
	
	public String getUsername() {
		return username;
	}
	
	public String getSecret() {
		return secret;
	}
	
	public void setUsername(String username) {
		this.username = username;
	}
	
	public void setSecret(String secret) {
		this.secret = secret;
	}
	
	public boolean isLogin() {
		return isLogin;
	}
	
	public void logout() {
		if (isLogin)
			isLogin = false;
	}
	
	public void login() {
		if (!isLogin)
			isLogin = true;
	}
	
	
	public void setNumOfAllow(int noa) {
		numOfAllow = noa;
	}
	
	public int getNumOfAllow() {
		return numOfAllow;
	}
	
}
