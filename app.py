import socket
import time
import tkinter as tk
import customtkinter as ct

def send_text_to_localhost(message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(('127.0.0.1', 8080))
            client_socket.sendall(message.encode('utf-8'))
            print(f"Sent message: {message}")

    except ConnectionRefusedError:
        print("Connection refused. Make sure the server is running.")

ct.set_appearance_mode("Dark")
ct.set_default_color_theme("blue")
class Window(ct.CTk):
    WIDTH = 1400
    HEIGHT = 820

    def __init__(self):
        super().__init__()
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.title("Firewall")
        self.rules = []
        self.realrules = []
        self.counter = 0
        self.indices = []
        self.createFrames()
        self.createLeftFrame()
        # self.createRightFrame()
    
    def createFrames(self):
        self.mainFrame = ct.CTkFrame(self)
        self.mainFrame.pack(fill="both", expand=True)
        self.mainFrame.grid_columnconfigure(0, weight=1)
        self.mainFrame.grid_columnconfigure(1, weight=13)

        self.LmainFrame = ct.CTkFrame(self.mainFrame)
        self.LmainFrame.grid(row=0, column=0, sticky="nsew",rowspan=1,padx=10,pady=10)
        for i in range(8):
            self.LmainFrame.grid_rowconfigure(i, weight=1)

        self.LFrames = []
        for i in range(9):
            self.LFrames.append(ct.CTkFrame(self.LmainFrame))
            self.LFrames[i].grid(row=i, column=0, sticky="nsew",padx=10,pady=10)
            self.LFrames[i].grid_columnconfigure(0, weight=10)
            self.LFrames[i].grid_columnconfigure(1, weight=1)
            self.LFrames[i].grid_columnconfigure(2, weight=1)

        self.ruleFrame = ct.CTkScrollableFrame(self.mainFrame)
        self.ruleFrame.grid(row=0, column=1, sticky="nsew",padx=10,pady=10)


    def createLeftFrame(self):
        self.Llabels = ["Source MAC", "Destination MAC", "Ether Type", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"]
        self.Lentries = []
        self.checkBoxes = []
        for i in range(8):
            ct.CTkLabel(self.LFrames[i], text=self.Llabels[i],font=("Arial",36),anchor="w").grid(row=0, column=0, sticky="nsew",padx=10,pady=10)
            self.checkBoxes.append(ct.CTkCheckBox(self.LFrames[i],text="", variable=tk.IntVar()))
            self.checkBoxes[i].grid(row=0, column=1, sticky="nsew",padx=10,pady=10)
            self.Lentries.append(ct.CTkEntry(self.LFrames[i],font=("Arial",36), width=300, state="disabled"))
            self.Lentries[i].grid(row=0, column=2, sticky="nsew",padx=10,pady=10)
            self.checkBoxes[i].configure(command=lambda i=i: self.toggle_entry(i))
        self.LFrames[8].grid_columnconfigure(0, weight=120)
        self.addButton = ct.CTkButton(self.LFrames[8], text="Add", command=self.add_rule,font=("Arial",36))
        self.addButton.grid(row=0, column=0, sticky="nsew",padx=10,pady=10)

       

    def toggle_entry(self, index):
        if self.checkBoxes[index].get() == 0:
            self.Lentries[index].delete(0, tk.END)
            self.Lentries[index].configure(state="disabled")
        else:
            self.Lentries[index].configure(state="normal")
            
    def add_rule(self):
        min_ind = 0
        #Find the first available index
        if len(self.indices) > 0:
            self.indices.sort()
            for i in range(len(self.indices)):
                if i != self.indices[i]:
                    min_ind = i
                    break
            if min_ind == 0:
                min_ind = self.indices[-1] + 1
            if 0 not in self.indices:
                min_ind = 0
        rule = []
        message = "ADD-"+str(min_ind)+"-"
        for i in range(8):
            if self.checkBoxes[i].get() == 1:
                rule.append(self.Llabels[i] + ": " + self.Lentries[i].get())
                message+=self.Lentries[i].get()+"-"
            else:
                message+="None-"

        if rule not in self.rules:
            self.rules.append(rule)
            rule = [min_ind] + rule
            self.realrules.append(rule)
            self.indices.append(min_ind)
            self.update_rules()
            message = message.rstrip("-")
            send_text_to_localhost(message)
            
        
    def update_rules(self):
        for widget in self.ruleFrame.winfo_children():
            widget.destroy()
        for i, rule in enumerate(self.rules):
            parsed_rule = "\n".join(rule)
            ct.CTkLabel(self.ruleFrame, text=f"----  {i}  ----\n {parsed_rule}",font=("Arial",24),anchor="w").pack()
            ct.CTkButton(self.ruleFrame, text="Delete", command=lambda i=i: self.delete_rule(i),font=("Arial",36)).pack()

    def delete_rule(self, index):
        self.rules.pop(index)
        r = self.realrules.pop(index)
        self.indices.remove(r[0])
        self.update_rules()
        message = "DEL-"+str(r[0])
        send_text_to_localhost(message)


if __name__ == "__main__":
    app = Window()
    app.mainloop()
