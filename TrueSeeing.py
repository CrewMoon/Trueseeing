
import unicodedata
import tkinter as tk
from tkinter import scrolledtext
from Crypto.Hash import SHA256


class TrueSeeingApp:



    def init_list(self):
        self.graphical_characters_ascii:list = []
        self.graphical_characters_ascii.extend(chr(i) for i in range(65, 91))
        self.graphical_characters_ascii.extend(chr(i) for i in range(97, 123))
        self.graphical_characters_ascii.extend(str(i) for i in range(0,10))
        self.graphical_characters_ascii.extend("""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~""")

        self.graphical_characters_unicode:list  = []
        self.harmful_format_unicode:list = []
        self.harmless_format:list = []
        for code_point in range(0, 0x110000):
            char = chr(code_point)
            category = unicodedata.category(char)
            if char.isascii() and not char.isprintable():
                self.harmless_format.append(char)
            elif char.isprintable():
                self.graphical_characters_unicode.append(char)
            else:
                self.harmful_format_unicode.append(char)

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("TrueSeeing")
        self.init_list()
        # Create GUI elements
        self.label_1 = tk.Label(self.root,text="original")
        self.label_1.grid(row = 0,column=0,padx=10,pady=10)
        self.text_area = tk.Text(self.root,height=2)
        self.text_area.grid(row=0,column=1,padx=10,pady=10)
        self.text_area.bind("<KeyRelease>",self.show_true_text)
        self.label_2 = tk.Label(self.root,text="True text")
        self.label_2.grid(row=1,column=0,padx=10,pady=10)
        self.text_area2 = tk.Text(self.root,height=2)
        self.text_area2.grid(row=1,column=1,padx=10,pady=10)

        # self.check_button = tk.Button(self.root, text="Check Text", command=self.check_text)
        # self.check_button.pack(pady=5)

        # self.signature_signature_label = tk.Label(self.root, text="Digital Signature:")
        # self.signature_signature_label.pack(pady=5)

        # self.signature = tk.Entry(self.root, width=60)
        # self.signature.pack(pady=5)



    def show_original_text(self):
        pass

    def show_true_text(self,event):
        originalText:str = self.text_area.get("1.0","end")
        self.text_area2.delete("1.0","end")
        originalText = originalText[0:len(originalText)-1]
        for c in originalText:
            if c in self.graphical_characters_ascii:
                self.text_area2.insert("end",c,"n")
                self.text_area2.tag_add("n","end")
            elif c in self.graphical_characters_unicode:
                self.text_area2.insert("end",c,"color1") 
                self.text_area2.tag_add("color1","end")
                self.text_area2.tag_config("color1",foreground="blue")
            elif c in self.harmful_format_unicode:
                real = repr(c)
                idx = self.text_area2.index("end-1c")
                self.text_area2.insert("end",real,"color2") 
                self.text_area2.tag_add("color2","end-1c")
                self.text_area2.tag_config("color2",foreground="red")
            elif c in self.harmless_format:
                idx = self.text_area2.index("end-1c")
                self.text_area2.insert("end",repr(c),"color3") 
                self.text_area2.tag_add("color3","end-1c")
                self.text_area2.tag_config("color3",foreground="green")

            
                
                
        

        
    def check_text(self):
        text = self.text_area.get("1.0", tk.END).strip()

        # Check for potentially harmful characters
        harmful_characters = self.detect_harmful_characters(text)

        if harmful_characters:
            self.display_warning("Potentially harmful characters detected!")
        else:
            # self.signature_label.config(text="Digital Signature:")
            # self.signature_entry.delete(0, tk.END)
            signature = self.generate_signature(text)
            self.signature.config(text=signature)
        

    def detect_harmful_characters(self, text):
        # Example: Detecting harmful characters (e.g., non-ASCII characters)
        harmful_characters = [char for char in text if ord(char) > 127]
        return harmful_characters

    def display_warning(self, message):
        warning_window = tk.Toplevel(self.root)
        warning_window.title("Warning!")

        warning_label = tk.Label(warning_window, text=message)
        warning_label.pack(padx=20, pady=10)

        ok_button = tk.Button(warning_window, text="OK", command=warning_window.destroy)
        ok_button.pack(pady=5)

    def generate_signature(self, text):
        # Example: Generating a digital signature using SHA-256
        hasher = SHA256.new()
        hasher.update(text.encode('utf-8'))
        signature = hasher.hexdigest()
        return signature
    
    def run(self):
        self.root.mainloop()
        


# Create the main window

app = TrueSeeingApp()
app.run()