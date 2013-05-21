import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.*;

public class Server {
	
	private static ServerSocket ipv6Server;
	
	static HttpURLConnection connection;
	
	public Server() throws IOException
	{
		ipv6Server = new ServerSocket(8080);
	}
	public static synchronized void send(String line)
	{
		try {
	        URL url = new URL(line);
	        connection = (HttpURLConnection) url.openConnection();
	        connection.connect();
	        connection.getInputStream();
	    } 
		catch (Exception e1) 
		{
	        e1.printStackTrace();	    
	    } 
		finally 
		{
	        connection.disconnect();
	    }
	}
	public static void main(String[] args) throws IOException
	{		
		new Server();
		Socket socket = null;
		ServerThread thread = null;
		System.out.println("hello");
		while(true)
		{
			socket = ipv6Server.accept();
			System.out.println("connected with: "+socket.getInetAddress().getHostAddress());
			thread = new ServerThread(socket);
			thread.start();			
		}
	}
	
}
