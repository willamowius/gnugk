import java.util.*;
import java.io.*;

public class logparser
{
	public static void main(String args[])
	{
		if (args.length <1)
		{
			ShowHelp();
			return;
		}

		boolean bOnly = false;
		int index = 0;

		for(index=0;index<args.length;index++)
		{
			if (args[index].compareTo("-o")==0 ||
				args[index].compareTo("--only")==0)
			{
				bOnly = true;
			}
		}

		logparser filter=new logparser();
		if (args.length == 1)
		{
			if (!filter.DoAction(args[0],"","",bOnly))
			{
				dout("Error while performing the filter");
				return;
			}
		}
		else if (args.length == 2)
		{
			if (!filter.DoAction(args[0],args[1],"",bOnly))
			{
				dout("Error while performing the filter");
				return;
			}
		}
		else
		{
			if (!filter.DoAction(args[0],args[1],args[2],bOnly))
			{
				dout("Error while performing the filter");
				return;
			}
		}


		dout("filter performed Succesfuly");
	}

	private static void ShowHelp()
	{
		dout("logparser usage:\r\n"+
							"\tjava logparser [-o , --only] <gklog_fileName> [out_prefix] [start_date<%Year/%Month/%Day]"+
							"\r\n"+
							"-o , --only prevent the log to extend to other dates which is the default behaviour\r\n"+
							"Example(s):\r\n"+
							"\tjava logparser out.txt\r\n"+
							"\tjava logparser out.txt e:\\\r\n"+
							"\tjava logparser out.txt e:\\ 2004/03/30\r\n"+
							"\tjava logparser --only out.txt . 2004/03/30");
	}

	public logparser()
	{}

	public boolean DoAction(String inFileName,String outFilePrefix,String startDate,boolean bOnly)
	{
		String				outFileName;
		FileInputStream		file_in=null;
		FileOutputStream	file_out=null;
		BufferedReader		reader=null;
		int					lines_read=0;
		int					lines_per_file=0;
		String				line;
		parsedate			parser;
		parsedate			startParser = null;
		String 				lastDate = "";

		if(outFilePrefix.length()<=0)
			outFilePrefix=".";
		if (!outFilePrefix.endsWith(""+File.separatorChar))
			outFilePrefix+=File.separatorChar;

		if (startDate.length()>0)
		{
			startParser = new parsedate(startDate);
		}

		try
		{
			file_in =new FileInputStream(inFileName);
			reader=new BufferedReader(new InputStreamReader(file_in));

			dout("$ input file "+inFileName+" opened succesfuly");
			while (true)
			{
				try
				{
					line= reader.readLine();
					if (line == null)
					{
						dout(getClass().getName()+"::End of File Reach()");
						break;
					}
					lines_read++;
					lines_per_file++;

					//2004/03/20 00:00:40.920	2	      RasSrv.cxx(2224)	GK	Read from 202.163.99.1:1025
					if (line.startsWith("2004/"))
					{
						parser = new parsedate(line);

						// This is the first date
						if (lastDate.length()<=0)
						{
							// If we are told to start from this particular date
							if ((startParser!=null && parser.compare(startParser))
								|| (startParser == null))
							{
								lastDate = line;

								outFileName = outFilePrefix+parser.getDay()+"_"+parser.getMonth()+"_"+parser.getYear()+".log";
								file_out=new FileOutputStream(outFileName);
								dout("$ First date found: "+parser);
								dout("$ FileName :"+outFileName);
							}
						}
						else
						{
							// If this is a different date
							if (parser.compare(lastDate) == false)
							{
								dout("$ File Closed, lines read :"+lines_per_file);
								// If this is the only file required then simply QUIT
								if(bOnly)
									break;

								file_out.close();

								lastDate = line;		// Set this line as last date
								lines_per_file = 0;		// Reset the lines per file

								outFileName = outFilePrefix+parser.getDay()+"_"+parser.getMonth()+"_"+parser.getYear()+".log";
								file_out=new FileOutputStream(outFileName);
								dout("$ New FileName :"+outFileName);
							}
						}
					}

					if (file_out != null)
					{
						line+="\r\n";
						file_out.write(line.getBytes());
					}
				}
				catch(Exception e1)
				{
					dout(getClass().getName()+"::Exception occured while reading: "+e1);
					break;
				}
			}

			reader.close();
			file_in.close();
			if (file_out != null)
				file_out.close();

			return true;
		}
		catch(Exception e)
		{
			dout(getClass().getName()+"::DoAction() there was an error while opening file :"+e);
			e.printStackTrace();
		}

		return false;
	}

	public static void dout(String s)
	{
		System.out.println(s);
	}
}

class parsedate
{
	String 	date;
	int 	year 	= 0;
	int 	month 	= 0;
	int 	day 	= 0;

	public parsedate(String d)
	{
		date = d;

		StringTokenizer tokenizer = new StringTokenizer(date,"/ \r\n");
		try
		{
			year 	= Integer.parseInt(tokenizer.nextToken());
			month 	= Integer.parseInt(tokenizer.nextToken());
			day 	= Integer.parseInt(tokenizer.nextToken());
		}
		catch(Exception e)
		{
			logparser.dout("$ "+getClass().getName()+"::parsedate()Exception->"+e);
		}
	}

	public int getMonth()
	{
		return month;
	}

	public int getYear()
	{
		return year;
	}

	public int getDay()
	{
		return day;
	}

	public boolean compare(String dd)
	{
		int y,m,d;

		y=m=d=0;
		StringTokenizer tokenizer = new StringTokenizer(dd,"/  \r\n");
		try
		{
			y = Integer.parseInt(tokenizer.nextToken());
			m = Integer.parseInt(tokenizer.nextToken());
			d = Integer.parseInt(tokenizer.nextToken());
		}
		catch(Exception e)
		{
			logparser.dout("$ "+getClass().getName()+"::compare()Exception->"+e);
			return false;
		}

		return (year==y && month==m && day==d);
	}

	public boolean compare(parsedate dd)
	{
		return (this.year==dd.year && this.month==dd.month && this.day==dd.day);
	}

	public String toString()
	{
		return ("Year:"+year+"-Month:"+month+"-Day:"+day);
	}
}