![made-with-python](https://img.shields.io/badge/Made%20with-Python3-brightgreen)

<!-- LOGO -->
<br />
<p align="center">
  <img src="https://user-images.githubusercontent.com/54740007/108192715-e5958c80-7114-11eb-8240-e884895bb45f.png" alt="Logo" width="80" height="80">

  <h3 align="center">Archive.org-Downloader</h3>

  <p align="center">
    Python3 script to download archive.org books in PDF format !
    <br />
    </p>
</p>


## About The Project

There are many great books available on https://openlibrary.org/ and https://archive.org/, however, you can only borrow them for 1 hour to 14 days and you don't have the option to download it as a PDF to read it offline or share it with your friends. I created this program to solve this problem and retrieve the original book in pdf format for FREE !

Of course, the download takes a few minutes depending on the number of pages and the quality of the images you have selected. You must also create an account on https://archive.org/ for the script to work.


## Getting Started
To get started you need to have python3 installed. If it is not the case you can download it here : https://www.python.org/downloads/

### Prerequisites
To run the the script you need install the python modules `requests`, `tqdm`, `img2pdf` with these commands :
```sh
pip install requests
pip install tqdm
pip install img2pdf
```

### Installation
Make sure you've already git installed. Then you can run the following commands to get the scripts on your computer:
   ```sh
   git clone https://github.com/MiniGlome/Archive.org-Downloader.git
   cd Archive.org-Downloader
   ```
   
## Usage
```sh
usage: downloader.py [-h] -e EMAIL -p PASSWORD -u URL [-r RESOLUTION] [-j]

optional arguments:
  -h, --help            show this help message and exit
  -e EMAIL, --email EMAIL
                        Your archive.org email
  -p PASSWORD, --password PASSWORD
                        Your archive.org password
  -u URL, --url URL     Link to the book (https://archive.org/details/XXXX). You can use this argument several times
                        to download multiple books
  -r RESOLUTION, --resolution RESOLUTION
                        Image resolution (10 to 0, 0 is the highest), [default 3]
  -j, --jpg             Output to individual JPG's rather then a PDF
```
The `email` and `password` fields are required, so to use this script you must have a registered account on archive.org.
The `-r` argument specifies the resolution of the images (0 is the best quality).
The PDF are downloaded in the current folder

### Example
```sh
python3 downloader.py -e myemail@tempmail.com -p Passw0rd -r 0 -u https://archive.org/details/IntermediatePython -u https://archive.org/details/horrorgamispooky0000bidd_m7r1 -u https://archive.org/details/elblabladelosge00gaut 
```
This command will download the 3 books as pdf in the best possible quality. To only downlaod the individual images you can use `--jpg`.

