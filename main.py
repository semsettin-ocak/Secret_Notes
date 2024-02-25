from tkinter import *
import base64
from tkinter import filedialog
from tkinter import messagebox
import os

main_screen = Tk()
main_screen.title("Secret Notes")
main_screen.minsize(width=400, height=300)
main_screen.resizable(width=False, height=False)
BGC = "light blue"
main_screen.config(bg=BGC, pady=15)
FONT = ("Courier New", 14, "bold")


def encode(key, message):
    enc = []
    for i in range(len(message)):
        key_c = key[i % len(key)]
        enc.append(chr((ord(message[i]) + ord(key_c)) % 256))

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# function to decode

def decode(key, message):
    dec = []
    message = base64.urlsafe_b64decode(message).decode()
    for i in range(len(message)):
        key_c = key[i % len(key)]
        dec.append(chr((256 + ord(message[i]) - ord(key_c)) % 256))

    return "".join(dec)


def encryption_func():
    taken_key = key_entry.get()
    taken_text = user_text.get("1.0", END)

    if title_entry.get() == "" or taken_text == "" or taken_key == "":
        messagebox.showerror("Warning", "Please enter all info")
    else:
        encrypted_text = encode(taken_key, taken_text)

        def save_file():
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text file (.txt)", "*.txt")])
            if file_path:
                try:
                    with open(file_path, "a") as f_f:
                        f_f.write(title_entry.get() + "\n" + encrypted_text + "\n \n")
                    user_text.delete("1.0", END)
                    key_entry.delete(0, END)
                    title_entry.delete(0, END)

                    def open_file_function():
                        os.startfile(os.path.abspath(file_path))
                    path_button = Button(command=open_file_function, bg=BGC, font=("Courier New", 10, "bold"))
                    path_button.config(text=f"The file saved as:\n{file_path}\n( Click to Open )")
                    path_button.pack()
                    messagebox.showinfo(message="File saved successfully")

                except Exception as e:
                    result_label.config(text=f"\nError! {str(e)}")
        save_file()


def decryption_func():
    taken_key = key_entry.get()
    taken_text = user_text.get("1.0", END)

    if taken_text == "" or taken_key == "":
        messagebox.showerror("Warning", "Enter both key and encrypted text")
    else:
        decrypted_text = decode(taken_key, taken_text)
        try:
            user_text.delete("1.0", END)
            key_entry.delete(0, END)
            user_text.insert("1.0", decrypted_text)
        except:
            messagebox.showerror("Warning!", "Check out your entries")


def exit_func():
    main_screen.destroy()


logo = PhotoImage(file="top_secret_image.png")
logo_label = Label(image=logo, bg=BGC)
logo_label.pack()

title = Label(text="Enter your title", font=FONT, bg=BGC, pady=10)
title.pack()

title_entry = Entry(width=40)
title_entry.focus()
title_entry.pack()

text_label = Label(text="Enter your secret", font=FONT, bg=BGC, pady=10)
text_label.pack()

user_text = Text(width=30, height=10)
user_text.pack()

key_label = Label(text="Enter your key", font=FONT, bg=BGC, pady=10)
key_label.pack()

key_entry = Entry(width=40)
key_entry.pack()

encryption_button = Button(text="Save & Encrypt", font=FONT, border=1, bg=BGC, pady=4, command=encryption_func)
encryption_button.pack()

decryption_button = Button(text="Decrypt", font=FONT, border=1, bg=BGC, pady=4, command=decryption_func)
decryption_button.pack()

exit_button = Button(text="Exit", font=FONT, border=1, bg=BGC, command=exit_func, pady=4, fg="red2")
exit_button.pack()

result_label = Label(bg=BGC, font=FONT)
result_label.pack()

main_screen.mainloop()
