<Query Kind="Program">
  <Connection>
    <ID>56bbded6-26c5-4c44-976f-7cc9b6aa88fe</ID>
    <Persist>true</Persist>
    <Driver Assembly="IQDriver" PublicKeyToken="5b59726538a49684">IQDriver.IQDriver</Driver>
    <Provider>System.Data.SQLite</Provider>
    <CustomCxString>Data Source=C:\ProgramData\PBL\Stkh\Client\local_storage;FailIfMissing=True</CustomCxString>
    <AttachFileName>&lt;CommonApplicationData&gt;\PBL\Stkh\Client\local_storage</AttachFileName>
    <DisplayName>PROD stkh</DisplayName>
    <IsProduction>true</IsProduction>
    <DriverData>
      <StripUnderscores>false</StripUnderscores>
      <QuietenAllCaps>false</QuietenAllCaps>
    </DriverData>
  </Connection>
  <Namespace>System</Namespace>
  <Namespace>System.IO</Namespace>
  <Namespace>System.Linq</Namespace>
  <Namespace>System.Security.Cryptography</Namespace>
  <Namespace>System.Text</Namespace>
</Query>

byte[] DecryptStkh(byte[] cipherData)
{
    byte[] keyData = { 0xeb, 0xf2, 0xf9, 0x00, 0x07, 0x0e, 0x15, 0x1c, 0x23, 0x2a, 0x31, 0x38, 0x3f, 0x46, 0x4d, 0x54,
                       0x5b, 0x62, 0x69, 0x70, 0x77, 0x7e, 0x85, 0x8c, 0x93, 0x9a, 0xa1, 0xa8, 0xaf, 0xb6, 0xbd, 0xc4 };

    int crc32 = BitConverter.ToInt32(cipherData, 0);
    cipherData = cipherData.Skip(4).ToArray();
    var decryptedData = default(byte[]);
		
    using (var rijndaelManaged = new RijndaelManaged { Key = keyData, Mode = CipherMode.ECB, Padding = PaddingMode.None })
    using (var memoryStream = new MemoryStream(cipherData))
    using (var cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Read))
    using (var outmemoryStream = new MemoryStream())
    {
        cryptoStream.CopyTo(outmemoryStream);
        decryptedData = outmemoryStream.ToArray();
    }
				
	// correct string length usins crc32 low byte
    var len = decryptedData.Length / 16;
    var lenFix = crc32 & 0xf;
    if (lenFix != 0)
	{
    	len = 16 * (len - 1) + lenFix;
		var decryptedDataLength = len;
    	decryptedDataLength = decryptedData[len - 1] == 0 ? len - 1 : decryptedDataLength;
    	decryptedData = decryptedData.Take(decryptedDataLength).ToArray();
	}

	return decryptedData;
}

string DecryptTLogEnc(byte[] cipherData)
{
	var decryptedData = DecryptStkh(cipherData);
	var dataLength = decryptedData.Length;
	if (decryptedData.Length > 2 && decryptedData[dataLength - 1] == 0)
		dataLength -= 1;

	return Encoding.UTF8.GetString(decryptedData, 0, dataLength);
}

string DecryptTHWCEnc(byte[] cipherData)
{
	var decryptedData = DecryptStkh(cipherData);
	var dataLength = decryptedData.Length;
	if (dataLength > 2 && decryptedData[dataLength - 1] == 0 && decryptedData[dataLength - 2] == 0)
		dataLength -= 2;

	return Encoding.Unicode.GetString(decryptedData, 0, dataLength).Replace((char)0xffff, ' ');
}

void ReadAllTLogEncs()
{
	var queryLog = from t in TLogEncs
				select new
				{
					Ev_time = DateTime.FromOADate((double)t.Ev_time),
					Ev_source = DecryptTLogEnc(t.Ev_source),
					Ev_desc= DecryptTLogEnc(t.Ev_desc)
				};
	queryLog.Dump();
}

void ReadAllTHWCEncs()
{
	var queryHw = from hw in THWCEncs
			select new
			{
				Hwc_str = DecryptTHWCEnc(hw.Hwc_str)
			};
	queryHw.Dump();
}

void Main()
{
	ReadAllTLogEncs();
	ReadAllTHWCEncs();
}
