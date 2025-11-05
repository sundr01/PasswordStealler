
# PasswordStealler

PasswordStealler is a collection of three projects that allow you to extract and decrypt passwords from saved connections. Each project corresponds to a different software:

## Projects

### 1) **winSCP - WSCPPasswordStealler**
- **Description:** Extracts and decrypts saved passwords from WinSCP connections.
- **Usage:** 
  To run the extractor for WinSCP, execute the following command:
  ```
  path	o\WSCPPasswordStealler.exe -p <path_to_config>
  ```
  The `-p` flag allows you to specify a custom path for the configuration files (by default, it uses the standard WinSCP config directory).

### 2) **SecureCRT - SCRTPasswordStealler**
- **Description:** Extracts and decrypts saved passwords from SecureCRT connections.
- **Usage:** 
  To run the extractor for SecureCRT, execute the following command:
  ```
  path	o\SCRTPasswordStealler.exe -p <path_to_config> -master <master_password> -prefix <prefix>
  ```
  - `-p` specifies a custom path for SecureCRT configuration files (defaults to the standard SecureCRT config directory).
  - `-master` allows you to change the default master password (use this if you know the master password).
  - `-prefix` lets you set a prefix (default is `03` which corresponds to newer versions of the vendor's encryption).

### 3) **MRemoteNg - MRNGPasswordStealler**
- **Description:** Extracts and decrypts passwords from MRNG saved connections.
- **Usage:** 
  To run the extractor for MRNG, execute the following command:
  ```
  path	o\MRNGPasswordStealler.exe -p <path_to_config> -m <master_password>
  ```
  - `-p` specifies a custom path for MRNG configuration files (defaults to the standard MRNG config directory).
  - `-m` specifies the master password if it's required to decrypt the data.

### 4) **FileZilla - FZPasswordStealler**
- **Description:** Extracts and decrypts passwords from MRNG saved connections.
- **Usage:** 
  To run the extractor for FileZilla, execute the following command:
  ```
  path	o\FileZillaPasswordStealler.exe -p <path_to_config> 
  ```
  - `-p` specifies a custom path for MRNG configuration files (defaults to the standard MRNG config directory).
  

