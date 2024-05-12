import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import os


class TrueSeeingApp:

    def __init__(self):
        """
        Initialize the TrueSeeingApp class
        """
        # Category 1: Set of graphical characters: English letters, digits, and punctuation marks
        self.harmless_graphical_characters: list = [chr(i) for i in range(32, 127)]
        # Category 2: Set of other graphical characters, which are potentially harmful
        self.harmful_graphical_characters: list  = []
        # Category 3: Set of harmless format characters: Horizontal Tab, Line Feed, Carriage Return
        self.harmless_format_characters: list = [chr(9), chr(10), chr(13)]
        # Category 4: Set of other format characters, which are potentially harmful
        self.harmful_format_characters: list = []
        self.harmful_format_characters.extend(chr(i) for i in range(0, 9))
        self.harmful_format_characters.extend(chr(i) for i in range(11, 13))
        self.harmful_format_characters.extend(chr(i) for i in range(14, 32))
        self.harmful_format_characters.extend(chr(i) for i in range(127, 160))
    
        # Set Category 2 and 4: Add all printable characters to the harmful graphical characters list
        for code_point in range(160, 0x110000):
            char = chr(code_point)
            if char.isprintable():
                self.harmful_graphical_characters.append(char)
            else:
                self.harmful_format_characters.append(char)

        # Set the default font for the GUI display
        self.default_font = "Arial"
        # Set the flag to check if the text is benign, default is True
        self.is_benign = True
        self.is_error = False
        # Set the root window of the GUI
        self.root = tk.Tk()
        self.GUI_init()
        self.GUI_choose_encoding_format()

    def manipulate_input(self, event):
        """
        Check the new input of the p2 text area, and
        only keep the English characters, digits, and punctuation marks
        Args:
            event: The event object, which contains the new input
        """
        # Check if there is actual input; avoid processing triggered by function keys
        if event.char == "" and event.keysym not in ["Return", "Enter", "Tab"]:
            return
        
        if event.keysym == "BackSpace":
            self.is_error = False
            self.text_area_p2.delete("insert-1c", "insert")
            self.show_original_text(event)
            self.check_benign()
            return "break"

        # Get the new input of the p2 text area
        new_input = event.char
        if new_input == "\r":
            new_input = "\n"

        # Check if the new input is a harmless format character
        if new_input in self.harmless_format_characters:
            self.text_area_p2.tag_config("greenColor",
                                         foreground="green",
                                         background="#C8C8A9")
            self.text_area_p2.insert("insert", repr(new_input)[1:-1], "greenColor")
            
        # Check if the new input is a harmless graphical character
        elif new_input in self.harmless_graphical_characters:
            self.text_area_p2.tag_config("normalColor",foreground="black")
            self.text_area_p2.insert("insert", repr(new_input)[1:-1], "normalColor")
        else:
            # Check if the new input is a harmful graphical character
            return "break"
        
        self.show_original_text(event)
        self.check_benign()
        return "break"


    def check_benign(self):
        """
        Check if the text is benign based on the text in the p1 text area
        """
        if self.is_benign is False and self.is_error is False:
            self.is_benign = True
            for c in self.text_area_p1.get("1.0", "end"):
                if c in self.harmful_graphical_characters:
                    self.is_benign = False
                    break
                elif c in self.harmful_format_characters:
                    self.is_benign = False
                    break
            if (self.is_benign):
                self.signature_button.config(state="normal")

    def show_original_text(self, event):
        """
        Show the original text in the p1 text area
        based on the true text in the p2 text area
        Args:
            event: The event object, which contains the new input
        """
        trueText = self.text_area_p2.get("1.0", "end")
        # remove the last character '\n' and evaluate control characters
        try:
            trueText = eval(repr(trueText[0:len(trueText) - 1]).replace('\\\\', '\\'))
        except Exception as e:
            # messagebox.showerror("Error", f"Error: {str(e)}")
            self.is_error = True
            print(e)
        self.text_area_p1.configure(state="normal")
        self.text_area_p1.delete("1.0", "end")
        self.text_area_p1.insert("end", trueText, "normalColor")
        self.text_area_p1.tag_add("normalColor", "end")


    def show_true_text(self, event):
        """
        Show the true text in the p2 text area based on the original text in the p1 text area
        Args:
            event: The event object, which contains the new input
        """
        originalText: str = self.text_area_p1.get("1.0", "end")
        self.text_area_p2.configure(state="normal")
        self.text_area_p2.delete("1.0", "end")
        originalText = originalText[0:len(originalText) - 1]  # remove the last character '\n'

        for c in originalText:
            real = repr(c)[1:-1]  # Get the string representation of the character
            if c in self.harmless_graphical_characters:
                self.text_area_p2.insert("end", real, "harmless_graphical")

            elif c in self.harmful_graphical_characters:
                self.text_area_p2.tag_config("harmful_graphical",
                                             foreground="blue",
                                             background="#83AF9B")
                self.text_area_p2.insert("end", real, "harmful_graphical")
                
                self.is_benign = False  # if the text contains other unicode chars, it is not benign

            elif c in self.harmless_format_characters:
                self.text_area_p2.tag_config("harmless_format",
                                             foreground="green",
                                             background="#C8C8A9")
                self.text_area_p2.insert("end", real, "harmless_format")

            elif c in self.harmful_format_characters:
                self.text_area_p2.tag_config("harmful_format",
                                             foreground="red",
                                             background="#FC9D9A")
                self.text_area_p2.insert("end", real, "harmful_format")
                
                self.is_benign = False  # if the text contains other format chars, it is not benign

        if (self.is_benign):
            self.signature_button.config(state="normal")
        else:
            self.signature_button.config(state="disabled")

    # init the GUI panel
    def GUI_init(self):
        self.root.title("TrueSeeing")
        self.root.iconbitmap("TrueSeeingIcon.ico")

        # Set the window size and put it in the center of the screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        size_geometry = "%dx%d+%d+%d" % (600, 850, (screen_width - 600) // 2, (screen_height - 850) // 2 - 40)
        self.root.geometry(size_geometry)

        # Make the window resizable or not
        self.root.resizable(True, True)

        self.frame_panel_labels = tk.Frame(self.root)
        self.frame_panel_labels.pack()

        self.label_encoding_format = tk.Label(self.frame_panel_labels,
                                              font=(self.default_font, 10),
                                              width=16,
                                              text="Encoding Format",
                                              relief="raised")
        self.label_encoding_format.pack(side="left", ipadx=3, ipady=1)

        self.label_text_examination = tk.Label(self.frame_panel_labels,
                                               font=(self.default_font, 10),
                                               width=16,
                                               text="Text Examination",
                                               relief="raised")
        self.label_text_examination.pack(side="left", ipadx=3, ipady=1)

        self.label_signature = tk.Label(self.frame_panel_labels,
                                        font=(self.default_font, 10),
                                        width=16,
                                        text="Signature Production",
                                        relief="raised")
        self.label_signature.pack(side="left", ipadx=3, ipady=1)


    # choose encode format panel
    def GUI_choose_encoding_format(self):
        """
        Create the panel to choose the encoding format
        """
        # init the panel head
        self.label_encoding_format.config(relief="sunken")

        self.encoding_format = tk.StringVar()
        self.encoding_format.set("UTF-8")

        # panel body
        self.frame_CEF = tk.Frame(self.root)
        self.frame_CEF.pack()

        self.label = tk.Label(self.frame_CEF,
                              text="Select one encoding format:",
                              font=(self.default_font, 12, "bold"))
        self.label.pack(pady=3, ipadx=3, ipady=1)

        self.radio_button_UTF_8 = tk.Radiobutton(self.frame_CEF,
                                                 font=(self.default_font, 10),
                                                 text="UTF-8",
                                                 variable=self.encoding_format,
                                                 value="UTF-8")
        self.radio_button_UTF_8.pack()

        self.radio_button_UTF_16 = tk.Radiobutton(self.frame_CEF,
                                                  font=(self.default_font, 10),
                                                  text="UTF-16",
                                                  variable=self.encoding_format,
                                                  value="UTF-16")
        self.radio_button_UTF_16.pack()

        self.button_choose_encoding_format = tk.Button(self.frame_CEF,
                                                       font=(self.default_font, 10),
                                                       width=8,
                                                       cursor="hand2",
                                                       text="Select",
                                                       command=lambda: self.GUI_text_examination(
                                                           self.encoding_format.get()))
        self.button_choose_encoding_format.pack()

        # panel bottom
        self.label_frame_SCF = tk.LabelFrame(self.frame_CEF,
                                             font=(self.default_font, 9),
                                             text="tips")
        self.label_frame_SCF.pack(fill="both")

        self.label_tip_CEF = tk.Label(self.label_frame_SCF,
                                      font=(self.default_font, 9),
                                      text="You have to choose one encoding format from UTF-8 and UTF-16.")
        self.label_tip_CEF.pack(padx=5, ipady=5)

    # text examination panel
    def GUI_text_examination(self, encoding_format):
        """
        Create the panel to examine the text
        Args:
            encoding_format: The encoding format chosen by the user
        """
        # init the panel head
        self.frame_CEF.pack_forget()
        self.label_encoding_format.config(relief="raised")
        self.label_text_examination.config(relief="sunken")

        # save the passed in encoding format
        self.encoding_format = encoding_format

        # panel body
        self.frame_TE = tk.Frame(self.root)
        self.frame_TE.pack()

        # p1
        self.label_p1 = tk.Label(self.frame_TE,
                                 width=16,
                                 font=(self.default_font, 12, "bold"),
                                 text="Original Text")
        self.label_p1.pack(pady=3)

        # p1 text area frame
        self.frame_text_area_p1 = tk.Frame(self.frame_TE)
        self.frame_text_area_p1.pack()

        self.scrollbar_p1 = tk.Scrollbar(self.frame_text_area_p1)
        self.scrollbar_p1.pack(side="right", fill="y")

        self.text_area_p1 = tk.Text(self.frame_text_area_p1,
                                    font=(self.default_font, 10),
                                    height=8,
                                    yscrollcommand=self.scrollbar_p1.set)
        self.text_area_p1.pack(padx=5)
        self.text_area_p1.config(state="disabled")

        self.scrollbar_p1.config(command=self.text_area_p1.yview)

        # get content from clipboard
        self.button_clipboard = tk.Button(self.frame_TE,
                                          width=24,
                                          font=(self.default_font, 10),
                                          text="Load from system clipboard",
                                          command=lambda: self.input_from_clipboard())
        self.button_clipboard.pack(pady=10)

        # get content from local file
        self.button_import_local_file = tk.Button(self.frame_TE,
                                                  width=24,
                                                  font=(self.default_font, 10),
                                                  text="Load from local file",
                                                  command=lambda: self.import_local_file(encoding_format))
        self.button_import_local_file.pack()

        # get content from typing, update p2 as long as enter any content in p1
        self.text_area_p1.bind("<KeyPress>", self.show_true_text)

        # p1 tips
        self.label_frame_TE_p1 = tk.LabelFrame(self.frame_TE,
                                               font=(self.default_font, 9),
                                               text="tips")
        self.label_frame_TE_p1.pack(fill="both", padx=4, pady=5)

        self.label_tip_p1 = tk.Label(self.label_frame_TE_p1,
                                     font=(self.default_font, 9),
                                     text="Input the text from your system clipboard or from the local file.\n"
                                          "The original appearance of the input shown in \"Origianl Text\".\n")
        self.label_tip_p1.pack()

        # p2
        self.label_p2 = tk.Label(self.frame_TE,
                                 width=16,
                                 font=(self.default_font, 12, "bold"),
                                 text="True Text")
        self.label_p2.pack(pady=3)

        # p2 text area frame
        self.frame_text_area_p2 = tk.Frame(self.frame_TE)
        self.frame_text_area_p2.pack()

        self.scrollbar_p2 = tk.Scrollbar(self.frame_text_area_p2)
        self.scrollbar_p2.pack(side="right", fill="y")

        self.text_area_p2 = tk.Text(self.frame_text_area_p2,
                                    font=(self.default_font, 10),
                                    height=8,
                                    yscrollcommand=self.scrollbar_p2.set)
        self.text_area_p2.pack(padx=5)

        self.scrollbar_p2.config(command=self.text_area_p2.yview)
        self.text_area_p2.config(state="disabled")

        # Disable the copy and paste function in the text area
        self.text_area_p2.bind("<Control-v>", lambda event: "break")
        self.text_area_p2.bind("<Control-v>", lambda event: "break", add=True)
        # Manipulate the input in the text area
        self.text_area_p2.bind("<Key>", self.manipulate_input, add=True)

        # p2 tips
        self.label_frame_TE_p2 = tk.LabelFrame(self.frame_TE, 
                                               font=(self.default_font, 9),
                                               text="tips")
        self.label_frame_TE_p2.pack(fill="both", padx=4)
        self.label_tip_p2 = tk.Label(self.label_frame_TE_p2,
                                     font=(self.default_font, 9),
                                     text=
                                     "Four categories of characters:\n"
                                     "1. English graphic characters: in black colour and on white background\n"
                                     "2. All other Unicode graphic characters: in dark blue colour and on light blue background\n"
                                     "3. Harmless Unicode format characters: in dark green colour and on light green background\n"
                                     "4. All other Unicode format characters that are potentially harmful: \n"
                                     "in dark red colour and on light red background\n"
                                     "Edit the text in \"True Text\" utill no categories 2 and 4 exist.\n"
                                     "As long as the situation is met, the signature button becomes enabled.\n")
        self.label_tip_p2.pack()

        # signature button
        self.signature_button = tk.Button(self.frame_TE,
                                          font=(self.default_font, 10),
                                          text="Generate signature",
                                          command=lambda: self.GUI_signature())
        self.signature_button.pack(padx=10, pady=10)


    def GUI_signature(self):
        """
        Create the panel to generate the signature
        """
        # init the panel
        self.frame_TE.pack_forget()
        self.label_text_examination.config(relief="raised")
        self.label_signature.config(relief="sunken")

        self.frame_S = tk.Frame(self.root)
        self.frame_S.pack()

        self.label_signature = tk.Label(self.frame_S,
                                        width=16,
                                        font=(self.default_font, 12, "bold"),
                                        text="Generated Signature")
        self.label_signature.pack(pady=3)

        # generate signature
        # signature frame
        self.frame_signature_text = tk.Frame(self.frame_S)
        self.frame_signature_text.pack()

        self.scrollbar_signature = tk.Scrollbar(self.frame_signature_text)
        self.scrollbar_signature.pack(side="right", fill="y")

        self.signature_text = tk.Text(self.frame_signature_text,
                                      font=(self.default_font, 10),
                                      height=10,
                                      yscrollcommand=self.scrollbar_signature.set)
        self.signature_text.pack(padx=5)

        self.scrollbar_signature.config(command=self.signature_text.yview)
        self.signature_text.config(state="disabled")

        self.generate_signature(self.text_area_p1.get("1.0", tk.END))

        # show algorithm
        self.algorithm_label = tk.Label(self.frame_S,
                                        font=(self.default_font, 10),
                                        text="Successfully generate the signature for this text\n"
                                             "in the above text area with the algorithm:\n"
                                             "RSA-FDH: RSA full-domain hash.\n")
        self.algorithm_label.pack(padx=10, pady=5)

        # algorithm tip
        self.label_frame_S_algorithm = tk.LabelFrame(self.frame_S,
                                                     font=(self.default_font, 9),
                                                     text="tips")
        self.label_frame_S_algorithm.pack(fill="both", padx=4)
        self.label_tip_algorithm = tk.Label(self.label_frame_S_algorithm,
                                            font=(self.default_font, 9),
                                            text="Find the file named \"private.pem\" for private key and \"public.pem\" for public key.\n")
        self.label_tip_algorithm.pack()

    # import local file to p1
    def import_local_file(self, encoding_format):
        """
        Import a local file to the p1 text area
        Args:
            encoding_format: The encoding format chosen by the user
        """
        self.text_area_p1.config(state="normal")
        local_file_path = filedialog.askopenfilename()
        # max file size 10MB
        if local_file_path:
            try:
                with open(local_file_path, "rb") as file:
                    local_file_content = file.read()
                self.text_area_p1.delete("1.0", "end")
                # 尝试用用户提供的编码格式解码文件内容
                decoded_content = local_file_content.decode(encoding_format)
                self.text_area_p1.insert("1.0", decoded_content)
                self.show_true_text(None)
            except UnicodeDecodeError as e:
                # 如果解码失败，弹出一个警告框
                messagebox.showerror("Encoding error", f"File encoding is not {encoding_format}")
            except Exception as e:
                # 处理其他可能的异常
                messagebox.showerror("Error", f"Error: {str(e)}")
        self.text_area_p1.config(state="disabled")
        self.text_area_p2.config(state="normal")

    def input_from_clipboard(self):
        """
        Get the content from the clipboard and put it in the p1 text area
        """
        self.text_area_p1.config(state="normal")
        try:
            clipboard_content = self.root.clipboard_get()
            self.text_area_p1.delete("1.0", "end")
            self.text_area_p1.insert("1.0", clipboard_content)
            self.show_true_text(None)
        except tk.TclError as e:
            messagebox.showerror("Clipboard Error", "Failed to get clipboard content.")
        self.text_area_p1.config(state="disabled")
        self.text_area_p2.config(state="normal")

    def check_text(self):
        text = self.text_area_p1.get("1.0", tk.END).strip()

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
        harmful_characters = [char for char in text if
                              char in self.harmful_graphical_characters or char in self.harmful_format_characters]
        return len(harmful_characters) > 0

    def display_warning(self, message):
        warning_window = tk.Toplevel(self.root)
        warning_window.title("Warning!")

        warning_label = tk.Label(warning_window, text=message)
        warning_label.pack(padx=20, pady=10)

        ok_button = tk.Button(warning_window, text="OK", command=warning_window.destroy)
        ok_button.pack(pady=5)

    # create public and private key pair
    def generate_keys(self, bits):
        private_key_path = "private.pem"
        public_key_path = "public.pem"
        private_key = None
        public_key = None
        # 检查私钥和公钥文件是否都存在
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # 导入现有密钥
            with open(private_key_path, "rb") as priv_file:
                private_key = RSA.import_key(priv_file.read())
            with open(public_key_path, "rb") as pub_file:
                public_key = RSA.import_key(pub_file.read())
        else:
            # 生成新的密钥对
            key = RSA.generate(bits, Random.new().read)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            # 保存私钥和公钥到文件
            with open(private_key_path, "wb") as priv_file:
                priv_file.write(private_key)
            with open(public_key_path, "wb") as pub_file:
                pub_file.write(public_key)

            # 重新导入密钥，确保一致性
            private_key = RSA.import_key(private_key)
            public_key = RSA.import_key(public_key)

        return private_key, public_key

    def sign_text(self, text: str):
        key_bits = 2048
        self.private_key, self.public_key = self.generate_keys(key_bits)
        # private_key = RSA.import_key(private_key_bytes)
        # public_key = RSA.import_key(public_key_bytes)
        modulus = self.private_key.n
        text_buffer = text.encode(encoding=self.encoding_format)
        hash_obj = SHA256.new(text_buffer)
        hashed_integer = int.from_bytes(hash_obj.digest(), byteorder="big")
        signature = pow(hashed_integer, self.private_key.d, self.private_key.n)
        return signature.to_bytes(key_bits // 8, byteorder="big")

    # only runs until all characters in text belong to category 1 or 3
    def generate_signature(self, text):
        if self.detect_harmful_characters(text):
            self.display_warning("Harmful characters exist")
            return
        signature = self.sign_text(text)
        self.signature_text.config(state="normal")
        self.signature_text.delete("1.0", tk.END)
        self.signature_text.insert("end", signature.hex())
        self.signature_text.config(state="disabled")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    # Create the main window
    app = TrueSeeingApp()
    app.run()