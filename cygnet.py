#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox

import json
import base64

import cryptography
from cryptography.hazmat.primitives.serialization import pkcs12

import sys
import os
import tempfile

import subprocess

class App(tk.Frame):
    def __init__(self,master):
        super().__init__(master)
        self.grid(row=0,column=0,padx=10,pady=10,sticky="news")
        self.columnconfigure(0,weight=0)
        self.columnconfigure(1,weight=1)

        self.name = tk.StringVar()
        self.name.set("")
        self.namelabel = tk.Label(self,text="Short name").grid(row=0, column=0)
        self.nameent = tk.Entry(self,textvariable=self.name).grid(row=0, column=1, columnspan=2, sticky="ew")

        tk.Label(self,text="VPN Server").grid(row=1,column=0)
        self.server = tk.StringVar()
        self.server.set("")
        self.serverent = tk.Entry(self,textvariable=self.server).grid(row=1,column=1, columnspan=2, sticky="ew")

        tk.Label(self,text="VPN type").grid(row=2, column=0)
        self.type = tk.StringVar()
        self.type.set("ikev2-eap-tls")
        self.typemenu = tk.OptionMenu(self,self.type,["ikev2-eap-tls"]).grid(row=2,column=1, columnspan=2, sticky="ew")

        self.certcn = tk.StringVar()
        tk.Label(self,text="Certificate").grid(row=3, column=0)
        self.certent = tk.Entry(self,textvariable=self.certcn,state=tk.DISABLED).grid(row=3, column=1, columnspan=2, sticky="ew")

        tk.Button(self,text="Import...", command=self.select_sswan).grid(row=4, column=0)
        tk.Button(self,text="Apply", command=self.apply).grid(row=4, column=1)
        tk.Button(self,text="Quit", command=self.master.destroy).grid(row=4, column=2)

    def select_sswan(self):
        file = str(filedialog.askopenfilename(title="Select a sswan profile", filetypes=(("StrongSWAN profile","*.sswan"),("All files","*.*"))))
        if file==None:
            return
        if os.path.exists(file):
            self.import_sswan(file)
        else:
            messagebox.showerror("Error",f"Could not read {file}")

    def import_sswan(self, file):
        with open(file,'r') as profile:
            settings = json.load(profile)
            self.server.set(settings['remote']['addr'])
            self.name.set(settings['name'])
            self.type.set(settings['type'])
            self.p12 = base64.b64decode(settings['local']['p12'])
        # Get CN from p12 TODO check what happens if encrypted
        bundle = pkcs12.load_pkcs12(self.p12,None)
        self.certcn.set(bundle.cert.certificate.subject)
        self.passwd=None

    def apply(self):
        with tempfile.TemporaryDirectory() as tempdir:
            #  TODO Find thumbprints of all ca certs
            xml = f"""
    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
                    <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
                    <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                    <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                    <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
            </EapMethod>
            <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                    <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                            <Type>13</Type>
                            <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
                                    <CredentialsSource>
                                            <CertificateStore>
                                                    <SimpleCertSelection>false</SimpleCertSelection>
                                            </CertificateStore>
                                    </CredentialsSource>
                                    <ServerValidation>
                                            <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
                                            <ServerNames>{self.server.get()}</ServerNames>
                                            <TrustedRootCA>2b 8f 1b 57 33 0d bb a2 d0 7a 6c 51 f7 0e e9 0d da b9 ad 8e </TrustedRootCA>
                                    </ServerValidation>
                                    <DifferentUsername>false</DifferentUsername>
                                    <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>
                                    <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName>
                                    <TLSExtensions xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">
                                            <FilteringInfo xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3">
                                                    <ClientAuthEKUList Enabled="true" />
                                            </FilteringInfo>
                                    </TLSExtensions>
                            </EapType>
                    </Eap>
            </Config>
    </EapHostConfig>
            """
            with open(tempdir+"\\eap.xml",'w') as eap:
                eap.write(xml)
            with open(tempdir+"\\certkey.pkcs12",'wb') as certkey:
                certkey.write(self.p12)
            with open(tempdir+"\\script.ps1",'w') as script:
                if self.passwd is None:
                    script.write('Import-PfxCertificate -FilePath certkey.pkcs12 -CertStoreLocation cert:\\CurrentUser\\My'+"\r\n")
                else:
                    script.write(f'$pwd = ConvertTo-SecureString "{self.passwd}" -AsPlainText -Force' + "\r\n")
                    script.write('Import-PfxCertificate -FilePath certkey.pkcs12 -CertStoreLocation cert:\\CurrentUser\\My -Password $pwd'+"\r\n")
                script.write(f'Add-VpnConnection -EapConfigXmlStream (gc eap.xml) -Name "{self.name.get()}" -serveraddress "{self.server.get()}" -TunnelType ikev2 -AuthenticationMethod eap'+"\r\n")
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "script.ps1"], capture_output=True,cwd=tempdir)
            print(out.stderr)
            print(out.stdout)
            print(f"tmpdir: {tempdir}")


if __name__ == '__main__':
    root = tk.Tk()
    root.rowconfigure(0,weight=1)
    root.columnconfigure(0,weight=1)
    app = App(root)
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        app.import_sswan(sys.argv[1])
    app.mainloop()
