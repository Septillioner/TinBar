import pyaes
import os
from hashlib import sha256
import struct
class TinCryptor:
	def __init__(self):
		self.DEFAULTNAME="SCC.key"
		self.InitKey="\x00"*32
		self.IV = "\x00"*16
		self.Encryptor = pyaes.AESModeOfOperationOFB(self.InitKey,iv=self.IV)
		self.Decryptor = pyaes.AESModeOfOperationOFB(self.InitKey,iv=self.IV)
		self.IK()
	def IK(self):
		if(not os.path.isfile(self.DEFAULTNAME)):
			with open(self.DEFAULTNAME,"wb") as fp:
				self.InitKey = os.urandom(32)
				self.IV = os.urandom(16)
				fp.write(self.InitKey+self.IV)
				self.rebuildEncryptor()
				self.rebuildDecryptor()
		else:
			with open(self.DEFAULTNAME,"rb") as fp:
				self.InitKey = fp.read(32)
				self.IV = fp.read(16)
				self.rebuildEncryptor()
				self.rebuildDecryptor()
	def GetHash(self):
		mt = sha256()
		mt.update(self.InitKey)
		mt.update(self.IV)
		return mt.digest()
	def rebuildEncryptor(self):
		self.Encryptor = pyaes.AESModeOfOperationOFB(self.InitKey,iv=self.IV)
	def rebuildDecryptor(self):
		self.Decryptor = pyaes.AESModeOfOperationOFB(self.InitKey,iv=self.IV)
	def Encrypt(self,data):
		return self.Encryptor.encrypt(data)
	def Decrypt(self,data):
		return self.Decryptor.decrypt(data)
	def rEncrypt(self,data):
		Encryptor = pyaes.AESModeOfOperationOFB(self.InitKey,iv=self.IV)
		return Encryptor.encrypt(data)
	def rDecrypt(self,data):
		Decryptor = pyaes.AESModeOfOperationOFB(self.InitKey,iv=self.IV)
		return Decryptor.decrypt(data)
def GetFilesInPath(path):
	f=[]
	for (dirpath, dirnames, filenames) in os.walk(path):
				for i in filenames:
					 f.append("%s\\%s"%(path,i))
	return f
class TinFile(object):
	"""docstring for TinFile"""
	def __init__(self, filename,filesize,file_address=0,sindex=0):
		super(TinFile, self).__init__()
		self.id = sindex
		self.filename=filename
		self.filesize=filesize
		self.file_address=filesize
		self.isAddressCalculated=False
	def CalculateAddress(self,padding):
		self.file_address=padding
		self.isAddressCalculated=True
class TinBar(object):
 	"""docstring for TinBar"""
 	def __init__(self, tin_cryptor):
 		super(TinBar, self).__init__()
 		self.tcr = tin_cryptor
 	def CreatHeaderOfFile(self,filename,filesize=0):
 		if(filesize==0):
 			filesize=os.path.getsize(filename)
 		headersizes = struct.pack("QQ",len(filename),filesize)
 		header=self.tcr.rEncrypt(headersizes+filename)
 		header = struct.pack("Q",len(header))+header
 		return header
 	#Structure EH: EncryptedHeaderLen 8B | EncryptedHeader
 	#Structure EH->: FilenameSize 2B | FileSize8B | Filename 
 	def AnalyzeHeaderOfFile(self,hof,sindex=0):
 		decrypted = self.tcr.rDecrypt(hof)
 		unpackeddata=struct.unpack("QQ",decrypted[0:16])
 		filename=decrypted[16:16+unpackeddata[0]]
 		filesize=unpackeddata[1]
 		return TinFile(filename,filesize,sindex=sindex)
 	def CreateHeader(self,file_paths):
 		buffer_ = ""
 		for file in file_paths:
 			buffer_+=self.CreatHeaderOfFile(file)
 		buffer_ = struct.pack("QQ",len(buffer_),len(file_paths))+buffer_
 		return buffer_
 	#Structure BufferLen 8B | FileCount 8B
 	def AnalyzeHeader(self,header):
 		filecount = struct.unpack("QQ",header[0:16])[1]
 		header = header[16:]
 		padding= len(header)
 		sindex = 0
 		eindex = 0
 		bufferindex = 0
 		bqt = []
 		for i in range(0,filecount):
 			sindex = bufferindex
 			eindex = bufferindex+8
 			ehl = struct.unpack("Q",header[sindex:eindex])[0]
 			filedata = self.AnalyzeHeaderOfFile(header[eindex:eindex+ehl],sindex=i)
 			filedata.CalculateAddress(padding)
 			bqt.append(filedata)
 			bufferindex = eindex+ehl
 			padding+=filedata.filesize
 		return bqt
 	def CreateTinBar(self,file_list):
 		file_list=self
def main():
	cryptor = TinCryptor()
	message = "selam"
	print "Cryptor Test Encrypt %s -> %s"%(message,cryptor.rEncrypt(message))
	print "Cryptor Test Decrypt %s -> %s"%(cryptor.rEncrypt(message),cryptor.rDecrypt(cryptor.rEncrypt(message)))
	tb = TinBar(cryptor)
	file = "files\\floppy.img"
	print "Header Test Encrypt %s -> %s"%(file,tb.CreatHeaderOfFile(file))
	print "Header Test Decrypt %s -> %s"%(tb.CreatHeaderOfFile(file),tb.AnalyzeHeaderOfFile(tb.CreatHeaderOfFile(file)[8:]))
	filelist = GetFilesInPath("files")
	header = tb.CreateHeader(filelist)
	print("Encrypted")
	print repr(header)
	print("Decrypted")
	filelist_ = tb.AnalyzeHeader(header)
	for file in filelist_:
		print "\t Id : %s - Filename : %s - Filesize : %s - Address : %s"%(file.id,file.filename,file.filesize,file.file_address)

if __name__ == '__main__':
	main()