
import TwiddlaAPI


twiddla = TwiddlaAPI.TwiddlaHelper('YourTwiddlaUsername', 'YourTwiddlaPassword')

# create a new whiteboard
try:
	sessionid = twiddla.CreateMeeting()
	print sessionid
except Exception as e:
	print(e)


# create a new whiteboard with a title, password and starting url
try:
	sessionid = twiddla.CreateMeeting("My Awesome Meeting", "hunter2", "http://www.google.com")
	print sessionid
except Exception as e:
	print(e)


# create a new user
try:
	userid = twiddla.CreateUser("newguy", "hunter2", "Roger Rogerson", "roger@example.org")
	print userid
except Exception as e:
	print(e)


# list active meetings 
try:
	csv = twiddla.ListActive()
	print csv
except Exception as e:
	print(e)


