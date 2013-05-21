import java.net.*;
import java.util.Random;
import java.util.StringTokenizer;
import java.awt.image.BufferedImage;
import java.io.*;


public class ServerThread extends Thread{
	Socket socket;
	public ServerThread(Socket s)
	{
		socket = s;
		System.out.println("you are here");
	}
	
	public void run()
	{
		try 
		{
			System.out.println("you are here2");
			BufferedReader r = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String line = r.readLine();
			System.out.println("heyy: "+line);
			if(line.charAt(0) == '#')
			{
				System.out.println("YOU ARE HEEEEERE");
				StringTokenizer tok = new StringTokenizer(line,"# ");
				String light = tok.nextToken();
				String status = tok.nextToken();
				Socket s = new Socket("fec0::3", 7);
				BufferedWriter w = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));
				w.write(light+" "+status);
				w.flush();
				s.close();
			}
			else
			{
				while(true)
				{
					StringTokenizer tok = new StringTokenizer(line," ,");
					int deviceId = Integer.parseInt(tok.nextToken());
					String value = tok.nextToken();
					Random ra = new Random();
					double val = ra.nextDouble();
					double valu = Double.parseDouble(value) + val;
					String url = "http://10.50.1.42:8888/httpds?__device=1&__sensor"+deviceId+"="+valu;
					System.out.println(url);
					Server.send(url);
					//socket.close();
					line = r.readLine();
					System.out.println("heyy: "+line);
				}
			}
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		finally
		{

		}
	}
}
