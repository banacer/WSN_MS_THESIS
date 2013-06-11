import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.net.*;
//hey banacer
public class Code
{
        public static void main(String[] args)
        {
        try
        {
                Socket s = new Socket("fec0::2",7);
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));
                writer.write("0 1");
                writer.flush();
                writer.close();
                s.close();
        }
        catch(Exception e)
        {
                e.printStackTrace();
        }
        }

}
