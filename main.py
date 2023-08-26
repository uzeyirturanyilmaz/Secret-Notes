from tkinter import *
from tkinter import messagebox
import base64


def saveAndEncryptNotes():
    title = titleEntry.get()
    message = inputText.get("1.0",END)
    masterSecret = masterSecretInput.get()

    if len(title) == 0 or len(message) == 0 or len(masterSecret) == 0 :
        messagebox.showwarning(title="Error!",message="Please enter all info.")
    else:
        #ecryaption
        message_bytes = message.encode('utf-8')
        masterSecret_bytes = masterSecret.encode('utf-8')


        combined_data = masterSecret_bytes + message_bytes


        messageEncrypted = base64.b64encode(combined_data).decode('utf-8')
        try:
            with open("mysecret.txt", "a") as dataFile:
                dataFile.write(f"\n{title}\n{messageEncrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as dataFile:
                dataFile.write(f"\n{title}\n{messageEncrypted}")
        finally:
            titleEntry.delete(0,END)
            masterSecretInput.delete(0,END)
            inputText.delete("1.0",END)


def decryptNotes():
    messageEncrypted = inputText.get("1.0", END)
    masterSecret = masterSecretInput.get()

    if len(messageEncrypted) == 0 or len(masterSecret) == 0:
        messagebox.showwarning(title="Error", message="Please enter all info.")
    else:
        try:

            encrypted_bytes = base64.b64decode(messageEncrypted.strip())


            masterSecret_bytes = masterSecret.encode('utf-8')


            combined_data = masterSecret_bytes + encrypted_bytes


            decryptedMessage = combined_data.decode('utf-8')


            inputText.delete("1.0", END)
            inputText.insert("1.0", decryptedMessage)
        except Exception as e:
            messagebox.showerror(title="Error", message="Decryption failed: " + str(e))

# UI

# UI
window = Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30)
img = PhotoImage(file="secret.png")
window.iconphoto(True, img)
FONT = ("Verdana", 15, "normal")


titleLabel = Label(text="Enter your title", font=FONT)
titleLabel.pack()

titleEntry = Entry(width=30)
titleEntry.pack()

inputLabel = Label(text="Enter your secret", font=FONT)
inputLabel.pack()

inputText = Text(width=35, height=10)
inputText.pack()

masterSecretLabel = Label(text="Enter master key", font=FONT)
masterSecretLabel.pack()

masterSecretInput = Entry(width=30)
masterSecretInput.pack()

saveButton = Button(text="Save & Encrypt",command=saveAndEncryptNotes)
saveButton.pack()

decryptButton = Button(text="Decrypt", command=decryptNotes)
decryptButton.pack()

window.mainloop()
