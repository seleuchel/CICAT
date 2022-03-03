from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
import time
import datetime
from fake_useragent import UserAgent
import re

sleeptime = 3
startreleasedate = datetime.datetime.strptime('2022-02-11',"%Y-%m-%d") # edit older
endreleasedate = datetime.datetime.strptime('2022-03-03',"%Y-%m-%d") # edit lately

CVE_restr = "CVE-[0-9]{4}-[0-9]{4,5}"


def check_date(date):
	Month = {"January": 1, "February":2, "March":3, "April":4, "May":5, "June":6, "July":7, "August":8,
			"September": 9, "October":10, "November":11, "December":12}
	l = date.split(" ")
	year = l[-1]
	day = l[-2].split(",")[0]
	month = Month[l[-3]]

	releasedate = datetime.datetime.strptime(str(year)+"-"+str(month)+"-"+str(day), "%Y-%m-%d")
	print("debug : ", releasedate)

	return releasedate


# set driver
class Crawl_ICSCERT:
	def __init__(self):
		chromeOptions = webdriver.ChromeOptions()
		chromeOptions.add_argument("--headless") # 브라우저 안보이도록
		chromeOptions.add_argument("--disable-gpu")

		# fake user agent
		#"user-agent=Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"
		ua = UserAgent()
		useragent = ua.random
		chromeOptions.add_argument(f'user-agent={useragent}')
		driver = webdriver.Chrome(ChromeDriverManager().install(), options=chromeOptions)

		self.driver = driver
		self.titletxt = []
		self.hreflist = []
		self.cveidlist = []

	def crawl_page_list(self):
		# site open
		url = "https://www.cisa.gov/uscert/ics/advisories?items_per_page=All"
		self.driver.get(url)

		s1 = "body > div > div.main-container.container.js-quickedit-main-content > div > section > div.region.region-content > div > div > div.view-content > div > ul > li > span.views-field.views-field-field-ics-docid-advisory > span"
		s2 = "body > div > div.main-container.container.js-quickedit-main-content > div > section > div.region.region-content > div > div > div.view-content > div > ul > li > span.views-field.views-field-title > span > a"

		# get data
		titles = self.driver.find_elements_by_css_selector(s1)
		hrefs = self.driver.find_elements_by_css_selector(s2)

		# get id / get href
		self.titletxt = [titles[i].text for i in range(len(titles))]
		self.hreflist = [hrefs[i].get_attribute("href") for i in range(len(titles))]


	def crawl_cvelid_list(self):
		for k in self.hreflist:
			self.driver.get(k)

			# check date
			sdate = "#ncas-header > div.submitted.meta-text"
			date = self.driver.find_element_by_css_selector(sdate).text #Original release date: February 24, 2022
			releasedate = check_date(date)

			rms = releasedate - startreleasedate
			emr = endreleasedate - releasedate

			if rms.days < 0:
				print("= END = ")
				break
			elif emr.days < 0:
				print("= START = ")
				continue
			else:
				s3 = "#ncas-content > div" # all page contents
				hdata = self.driver.find_element_by_css_selector(s3).text

				# get cveid list
				restr = re.findall(CVE_restr, hdata)
				self.cveidlist = self.cveidlist + restr

			time.sleep(sleeptime)
			print("------------")
		print("------------ CRWALING END ------------")
		return self.cveidlist



if __name__=="__main__":
	crawlics = Crawl_ICSCERT()
	crawlics.crawl_page_list()
	cveidlist = crawlics.crawl_cvelid_list()

	print("------------ RESULT ------------")
	print(cveidlist)

	# save cve list to txt
	with open("./CVEIDLIST_ICSCERT.txt","w", encoding="utf-8") as f:
		for cveid in cveidlist:
			f.write(cveid + "\n")
		f.close()
