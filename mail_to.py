import sys
import os
from smtplib import SMTP
from email.message import EmailMessage

filename = sys.argv[1]

msg = EmailMessage()
msg["From"] = os.getenv('SMTP_FROM')
msg["Subject"] = "Flan scan finished"
msg["To"] = os.getenv('SMTP_TO')
msg.set_content("This is the message body")
msg.add_attachment(open(filename, "r", encoding="utf8").read(), filename=filename)

print("filename:" + filename)
print("SMTP_SERVER:" + os.getenv('SMTP_SERVER'))

with SMTP(host=os.getenv('SMTP_SERVER'), port=587) as smtp:
    smtp.starttls()
    smtp.login(user=os.getenv('SMTP_USER'), password=os.getenv('SMTP_PASSWORD'))
    smtp.send_message(msg)
    smtp.quit()
