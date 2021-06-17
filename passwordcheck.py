import tkinter, os, hashlib

class PasswordCheck:
    def __init__(self):
        self.construct()
        self.populatePath()
        self.selectVersion()

    def construct(self):
        ''' Will create the gui used to check compromised passwords '''
        # Creating and configuring window
        self.window = tkinter.Tk()
        self.window.minsize(width=100, height=500)
        self.window.resizable(False, False) # currently the window will be set to be non-resizable

        ''' Path Frame '''
        # Path entities
        self.path_frame = tkinter.Frame(padx=20, pady=10)
        self.path_label = tkinter.Label(master=self.path_frame, text="File Path:")

        pathValue = tkinter.StringVar()
        pathValue.trace("w", lambda name, index, mode, pathValue=pathValue: self.selectVersion())
        self.path_entry = tkinter.Entry(master=self.path_frame, width=100, textvariable=pathValue)

        # Grid config
        self.path_label.grid(row=0, column=0, sticky='w')
        self.path_entry.grid(row=1, column=0)
        self.path_frame.grid(row=0, column=0, sticky='w')

        ''' Version Frame '''
        # Version entities
        self.version_frame = tkinter.Frame(padx=20, pady=10)
        self.version_label = tkinter.Label(master=self.version_frame, text="Version:")

        # Used to track state of check buttons
        self.sha1Var = tkinter.IntVar()
        self.ntlmVar = tkinter.IntVar()
        self.bothVar = tkinter.IntVar()

        self.sha1_cb = tkinter.Checkbutton(master=self.version_frame, variable=self.sha1Var, command=self.toggleSHA1, text="SHA1")
        self.ntlm_cb = tkinter.Checkbutton(master=self.version_frame, variable=self.ntlmVar, command=self.toggleNTLM, text="NTLM")
        self.both_cb = tkinter.Checkbutton(master=self.version_frame, variable=self.bothVar, command=self.toggleBoth, text="Both")

        # Grid config
        self.version_label.grid(row=0, column=0)
        self.sha1_cb.grid(row=1, column=0)
        self.ntlm_cb.grid(row=1, column=1)
        self.both_cb.grid(row=1, column=2)
        self.version_frame.grid(row=1, column=0, sticky='w')

        ''' PWs to Check '''
        # PW entities
        self.pws_frame = tkinter.Frame(padx=20, pady=10)
        self.pws_label = tkinter.Label(master=self.pws_frame, text="Passwords to Check:")
        self.pws_text = tkinter.Text(master=self.pws_frame, width=75, height=15)

        # Grid config
        self.pws_label.grid(row=0, column=0)
        self.pws_text.grid(row=1, column=0)
        self.pws_frame.grid(row=2, column=0)

        ''' Output '''
        # Output entities (matched PWs)
        self.output_frame = tkinter.Frame(padx=20, pady=10)
        self.output_label = tkinter.Label(master=self.output_frame, text="Found Passwords:")
        self.output_text = tkinter.Text(master=self.output_frame, width=75, height=15)

        # Grid config
        self.output_label.grid(row=0, column=0)
        self.output_text.grid(row=1, column=0)
        self.output_text.config(state=tkinter.DISABLED)
        self.output_frame.grid(row=3, column=0)

        ''' Run Button '''
        self.control_frame = tkinter.Frame(padx=20, pady=10)
        self.runButton = tkinter.Button(master=self.control_frame, text="HaveYouBeenPwned?", command=self.checkPasswords)

        self.runButton.grid(row=0, column=0)
        self.control_frame.grid(row=4, column=0)

    def populatePath(self):
        ''' Attempts to identify the path for a pwned passwords txt file; Checks the downloads, desktop,
            and documents directories prioritizing a file ordered by hash vs. ordered by count '''

        orderTypes = ["ordered-by-hash", "ordered-by-count"]
        directories = ["Downloads", "Desktop", "Documents"] # The directories being checked
        homePath = os.path.expanduser("~")
        
        for orderType in orderTypes:
            for directory in directories:
                path = homePath + "\\" + directory

                for fileName in os.listdir(path=path):
                    if orderType in fileName and fileName.endswith(".txt"):
                        self.path_entry.insert(0, path + "\\" + fileName)
                        return
                
    def selectVersion(self):  
        ''' Attempts to identify the best hash function to use based on the
            name of the password file, if present '''

        path = self.path_entry.get().lower()

        if "sha1" in path:
            self.sha1Var.set(1)
            self.toggleSHA1()
            
        elif "ntlm" in path:
            self.ntlmVar.set(1)
            self.toggleNTLM()

        # Handles no version being checked
        self.checkHashVersion()

    def checkPasswords(self):
        ''' Checks the user provided plaintext passwords '''
        # Deletes any previous content in the output text box
        self.output_text.config(state=tkinter.NORMAL)
        self.output_text.delete("1.0","end")
        self.output_text.config(state=tkinter.DISABLED)

        # Retrieves user specified passwords
        passwords = self.pws_text.get("1.0", "end").strip().split('\n')

        # Skips when there are no entries
        if passwords == ['']:
            return

        # Counter to be used to identify if all provided passwords have been found (for linear search)
        numToFind = len(passwords)

        # Handles no version being checked
        self.checkHashVersion()

        # List of hashes to check
        hashes = []

        # Dictionary of hashes to plaintext passwords
        hashToPass = {}

        bothFlag, sha1Flag, ntlmFlag = self.bothVar.get(), self.sha1Var.get(), self.ntlmVar.get()          

        for password in passwords:
            # Generates sha1 hash
            if bothFlag or sha1Flag:
                h = self.sha1(password)
                hashToPass[h] = password
                hashes.append(h)

            # Generates ntlm hash
            if bothFlag or ntlmFlag:
                h = self.ntlm(password)
                hashToPass[h] = password
                hashes.append(h)

        # Changes run button text to indicate a running state
        self.runButton.config(text="Running ...")

        # Opens file of haveibeenpwned hashes 
        with open(self.path_entry.get(), 'r') as inF:

            # If the user has downloaded and specified the sorted by hash file, a logarithmic search will be performed
            if "ordered-by-hash" in self.path_entry.get().lower():
                startIndex = 0
                endIndex = inF.seek(0, 2) # This will be the very end of the file
                self.checkPasswordsLogarithmic(inF, startIndex, endIndex, hashes, hashToPass)

            # Otherwise, a linear search will be performed
            else:
                self.checkPasswordsLinear(inF, hashes, hashToPass, numToFind)

        self.runButton.config(text="HaveYouBeenPwned?") # Changing the run button text back to indicate the pass check has completed

    def checkPasswordsLinear(self, inF, hashes, hashToPass, numToFind):
        ''' Will perform a linear search through the pwned hash file checking provided passwords '''
        
        for line in inF:
            line = line.strip().split(':')

            pwnedHash = line[0]
            timesPwned = line[1]
                
            for passHash in hashes:
                if passHash == pwnedHash: # A match!
                    hashes.remove(passHash) # Removes matched hash to prevent future checks against it
                    numToFind -= 1 # Decrementing the counter that tracks how many passwords are left to find

                    # Updating output with the found password
                    self.modifyFoundPassOutput(hashToPass[passHash], timesPwned)

                    # If all passwords are found, the script will not continue to looping to the end of the file
                    if numToFind == 0:
                        return

                    break # go to next line/hash in file
                
    def checkPasswordsLogarithmic(self, inF, startIndex, endIndex, hashes, hashToPass):
        ''' Will perform a logarithmic search through the pwned hash file checking provided passwords '''
        # For the following base case
        inF.seek(startIndex)
        inF.readline()

        # Base case checks if the lines associated with startIndex/endIndex are next to eachother
        if endIndex == inF.tell():
            # Comparing remaining hashes against the last two remaining lines
            
            # Low hash (startIndex line)
            inF.seek(startIndex)
            line = inF.readline().strip()
            line = line.split(':')
            
            lowHash = line[0]
            timesPwnedLow = line[1]

            # High hash (endIndex line)
            inF.seek(endIndex)
            line = inF.readline().strip()

            endHash = None

            # Handling if endIndex is still pointing to the end of the file
            if line != '':
                line = line.split(':')

                highHash = line[0]
                timesPwnedHigh = line[1]

            for passHash in hashes:
                if passHash == lowHash:
                    # Updating output with the found password
                    self.modifyFoundPassOutput(hashToPass[passHash], timesPwnedLow)
                elif passHash == endHash:
                    # Updating output with the found password
                    self.modifyFoundPassOutput(hashToPass[passHash], timesPwnedHigh)
                    
            return

        # Getting the middle index between startIndex and endIndex
        mid = (endIndex + startIndex) // 2
        inF.seek(mid)

        # Sets up mid to be the first char in curr line
        while inF.read(1) != '\n':
            mid -= 1
            inF.seek(mid)

        mid = inF.tell()

        line = inF.readline().strip()
        line = line.split(':')

        pwnedHash = line[0]
        timesPwned = line[1]

        # Lists will hold hashes that still need to be checked based on if they are alphabetically greater than or lesser the hash at the mid position in the file
        lowCheck, highCheck = [], []

        for passHash in hashes:
            if passHash == pwnedHash:
                # Updating output with the found password
                self.modifyFoundPassOutput(hashToPass[passHash], timesPwned)
            elif passHash < pwnedHash:
                lowCheck.append(passHash)
            else:
                highCheck.append(passHash)

        if len(lowCheck) > 0:
            self.checkPasswordsLogarithmic(inF, startIndex, mid, lowCheck, hashToPass)

        if len(highCheck) > 0:
            self.checkPasswordsLogarithmic(inF, mid, endIndex, highCheck, hashToPass)

    def modifyFoundPassOutput(self, password, timesPwned):
        # Updating output text box to show the identified password
        self.output_text.config(state=tkinter.NORMAL)
        self.output_text.insert("end", password + " has been pwned " + timesPwned + " times\n")
        self.output_text.update()
        self.output_text.config(state=tkinter.DISABLED)
    
    def sha1(self, password):
        ''' Creates and returns the sha1 hash of the provided password '''
        return hashlib.sha1(password.encode()).hexdigest().upper()
        
    def ntlm(self, password):
        ''' Creates and returns the ntlm hash of the provided password '''
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest().upper()

    def toggleSHA1(self):
        self.ntlmVar.set(0)
        self.bothVar.set(0)

    def toggleNTLM(self):
        self.sha1Var.set(0)
        self.bothVar.set(0)

    def toggleBoth(self):
        self.sha1Var.set(0)
        self.ntlmVar.set(0)

    def checkHashVersion(self):
        ''' If no version is chosen, Both will be set '''
        if not self.sha1Var.get() and not self.ntlmVar.get() and not self.bothVar.get():
            self.bothVar.set(1)
    
if __name__ == "__main__":
    pass_check = PasswordCheck()

    # Added to allow tkinter window to remain open when the python file is run directly/when run packaged as an exe
    input("Hit enter or close this window when finished ...")
