from collections import OrderedDict
from lxml import etree
import os, signal, sys
import argparse
import xlsxwriter

def get_vulners_from_xml(xml_content):
	vulnerabilities = dict()
	vulner_id=""

	Device=""
	FoundID=""
	DID=""
	IP=""

	CVScore=""

	btid=""
	crid=""

	p = etree.XMLParser(huge_tree=True)
	root = etree.fromstring(text=xml_content, parser=p)
	
	#Try and pull the client id's needed for the report.
	for header in root:
		if header.tag=="Header":
			for block in header:
				if block.tag=="Subtitle":
					btid=block.text
					if btid.find("PT"):
						btid=(btid[btid.find("PT"):btid.find(" ",btid.find("PT"))])
						#print(btid)
					else:
						btid=""

				if block.tag=="ClientReference":
					crid=block.text
					#print(crid)

	for block in root:
		if block.tag == "Vulnerabilities":
			vulner_struct = dict()
			for report_host in block:
				vulner_struct['BTJobCode'] = btid
				vulner_struct['IRMJobCode'] = crid

				if report_host.tag =="Title":
					vulner_struct['Title'] = report_host.text
					vulner_id = vulner_struct['Title']
				if report_host.tag=="ProcessFailure":
					vulner_struct['ProcessFailure'] = report_host.text
				if report_host.tag=="Description":
					vulner_struct['Description'] = report_host.text
				if report_host.tag=="LongRecommendation":
					vulner_struct['LongRecommendation'] = report_host.text
				if report_host.tag=="ShortRecommendation":
					vulner_struct['ShortRecommendation'] = report_host.text
				if report_host.tag=="CommonVulnerabilitiesAndExposureReferences":
					vulner_struct['CommonVulnerabilitiesAndExposureReferences'] = report_host.text
				if report_host.tag=="CommonVulnerabilityScoringSystemReferences":
					vulner_struct['CommonVulnerabilityScoringSystemReferences'] = report_host.text
				
					#Check to see if the CVSS score is a float/number
					try:
						x = int(float(vulner_struct['CommonVulnerabilityScoringSystemReferences']))
						y = isinstance(x, (int, float))
						
						CVScore=report_host.text
						#If we're good set to true
						floater=True
					except:
						floater=False

					#If we've not passed the first validation check to see whether the number is between () e.g. (4.5) then some text
					if floater==False:
						a=str(vulner_struct['CommonVulnerabilityScoringSystemReferences'])
						b=a[a.find("(")+1:a.find(")")]
						#print(b)
						try:
							x = int(float(b))
							y = isinstance(x, (int, float))
							CVScore=b
							#If the number between () then set to true
							floater=True
						except:
							floater=False

					#If we've not passed the 2nd validation check - IRM RWT CVS Tool
					#https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:H&version=3.1 5.6 - AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:H
					if floater==False:
						a=str(vulner_struct['CommonVulnerabilityScoringSystemReferences'])
						if a.find("https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=")==0:
							b=a[a.find("&version=3.1")+13:a.find(" - ",int((a.find("&version=3.1")+13)))]
							#print(b)
							try:
								x = int(float(b))
								y = isinstance(x, (int, float))
								CVScore=b
								#If the number between () then set to true
								floater=True
							except:
								floater=False


					#If we're good here, convert the numbers to the other scoring system
					if floater==True:
						try:
							#Convert CVSS Score to BT Scoring System
							if int(float(CVScore))>=9 and int(float(CVScore))<=10:
								vulner_struct['BTDef']="A"
							if int(float(CVScore))>=7 and int(float(CVScore))<=8.9:
								vulner_struct['BTDef']="B"
							if int(float(CVScore))>=4 and int(float(CVScore))<=6.9:
								vulner_struct['BTDef']="C"
							if int(float(CVScore))>=0 and int(float(CVScore))<=3.9:
								vulner_struct['BTDef']="D"
						except:
							print("[!]Something went wrong processing the CVE scores...")
					#Set the value to Z to indicate something wrong
					else:
						vulner_struct['BTDef']="Z"
						print("[!]Unable to process CVSS score - "+a+" - please either use number on its own e.g. 3.9 or if using score and vector, prefix score in brackets e.g. (3.9) AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:H")
					
				if report_host.tag=="FoundVulnerabilityID":
					vulner_struct['FoundVulnerabilityID'] = report_host.text
					Devices=[]
					for rblock in root:
						if rblock.tag == "VulnerabilityDevices":
							for stuff in rblock:
								if(stuff.tag)=="FoundVulnerabilityID":
									FoundID=stuff.text
								if(stuff.tag)=="DeviceID":
									Device=stuff.text

						if FoundID==vulner_struct['FoundVulnerabilityID']:
							for sblock in root:
								if sblock.tag == "Devices":

									for sstuff in sblock:
										if(sstuff.tag)=="DeviceID":
											DID=sstuff.text

										if(sstuff.tag)=="Instance":
											IP=sstuff.text

									if DID==Device:
										Devices.append(IP)

								Devices=list(OrderedDict.fromkeys(Devices))
								listToStr = ' '.join(map(str, Devices))

								vulner_struct['Devices']=listToStr
                
			if not vulner_id in vulnerabilities:
				vulnerabilities[vulner_id] = vulner_struct

	return(vulnerabilities)

def banner():
	print("""                               
               

 .----------------.  .----------------.  .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| |     ______   | || |      __      | || | ____   ____  | || |  _________   | || |  _______     | |
| |   .' ___  |  | || |     /  \     | || ||_  _| |_  _| | || | |_   ___  |  | || | |_   __ \    | |
| |  / .'   \_|  | || |    / /\ \    | || |  \ \   / /   | || |   | |_  \_|  | || |   | |__) |   | |
| |  | |         | || |   / ____ \   | || |   \ \ / /    | || |   |  _|  _   | || |   |  __ /    | |
| |  \ `.___.'\  | || | _/ /    \ \_ | || |    \ ' /     | || |  _| |___/ |  | || |  _| |  \ \_  | |
| |   `._____.'  | || ||____|  |____|| || |     \_/      | || | |_________|  | || | |____| |___| | |
| |              | || |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------'              

  
Because RWT Doesn't do CAVE Reports and they're not quick to do manually :-p
Version 0.1ad
@rd_pentest


""")


def main():

	#Show Banner (it's not a legit tool without an ascii banner)
	banner()

	#Get command line args
	p = argparse.ArgumentParser("./caver -f file.repdef ", formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=20,width=150),description = "Convert Repdef to CAVE")

	p.add_argument("-f", "--filename", dest="filename", help="Enter name of nessus file to parse")
	p.add_argument("-out", "--out", dest="out", help="Enter name of file to save as e.g. somthingcool.xlsx (if no output filename is specified saves as caver.xlsx in cwd")

	args = p.parse_args()

	if args.filename!="":
		#Open repdef file to parse
		file_path = args.filename
		f = open(file_path, 'r')
		xml_content = f.read()
		f.close()

		#Call xml repdef parse function
		vulners = get_vulners_from_xml(xml_content)

		#Setup devices list variable
		devices=[]

		# Create a workbook and add a worksheet.
		if args.out!="":
			workbook = xlsxwriter.Workbook(args.out)
		else:
			workbook = xlsxwriter.Workbook('caver.xlsx')
		
		worksheet = workbook.add_worksheet("CAVER Report Sheet")

		# Start from the first cell. Rows and columns are zero indexed.
		row = 0
		col = 0
		bold = workbook.add_format({'bold': True})

		#Finding*	Description*	Recommendation*	CVSS	CVE Ref*	Thread Level Category
		worksheet.write(row, col,"Finding",bold)
		worksheet.write(row, col+1,"Description",bold)
		worksheet.write(row, col+2,"Recommendation",bold)
		worksheet.write(row, col+3,"CVSS",bold)
		worksheet.write(row, col+4,"CVE Ref",bold)
		worksheet.write(row, col+5,"Thread Level Category",bold)

		row=1
		
		#Cycle through all vulnerabilities and write the relevant issues to xlsx
		for vulner_id in vulners:
			try:
				worksheet.write(row, col,(vulners[vulner_id]["Title"]))
				worksheet.write(row, col+1,"Process Failure: "+(vulners[vulner_id]["ProcessFailure"])+"\r"+"Description: "+(vulners[vulner_id]["Description"])+"\r"+"Devices: "+(vulners[vulner_id]["Devices"]))
				worksheet.write(row, col+2,(vulners[vulner_id]["ShortRecommendation"]))
				worksheet.write(row, col+3,(vulners[vulner_id]["CommonVulnerabilityScoringSystemReferences"]))
				worksheet.write(row, col+4,(vulners[vulner_id]["CommonVulnerabilitiesAndExposureReferences"]))
				worksheet.write(row, col+5,(vulners[vulner_id]["BTDef"]))

				row += 1

			except:
				pass

		workbook.close()
		print("[*]Done...")

#Routine handles Crtl+C gracefully
def signal_handler(signal, frame):
	print ("\nCtrl+C pressed.. exiting...")
	sys.exit()

#Loads up main
if __name__ == '__main__':
	#Setup Signal handler in case of Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
	#Call main routine.
	main()