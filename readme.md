# Phisycal Security

## Bakcup
* split file into some files that each file has 4 lines 
* encrypt each file with password and AES
* encode each encrypted file with base64
* generate qrcode from every base64 files


## Restore
* read qrcode from every base64 files
* decode each encrypted files with base64
* using password for decrypt each file 
* concatenation files into 1 file

## before using script change password in main.py file:
```password = 'YOUR_STRONG_PASSWORD'```
### install requirement packages
```
pip3 install -r requirements.txt
```

sample example:
for encryption
```
./python3 encrypt YOUR_FILE_NAME
```

for decryption:
```
./python3 decrypt 
```
