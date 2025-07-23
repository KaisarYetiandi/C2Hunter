# C2Hunter 
![screenshot](https://github.com/KaisarYetiandi/C2Hunter/blob/main/assests/icons/c2hunter.png)
**C2Hunter** adalah tools buat ngintip domain-domain mencurigakan yang mungkin terkait dengan C2 (server malware atau rat) server dari sebuah IP target. Tools ini bakal ngambil data dari VirusTotal, analisis, terus kasih laporan lengkap plus visualisasi keren!

## Fitur Utama

- Fetching domain terkait dari IP target via VirusTotal API  
- Analisis otomatis indikator C2 (Command & Control)  
- Deteksi risiko domain (malicious, suspicious, dll)  
- Generate report dalam format JSON & Markdown  
- Visualisasi hubungan domain dalam bentuk graph interaktif  
- Limit jumlah domain yang di-scan (biar ga kebanyakan)

## ⚙️ Cara Install

1. **Clone Repository**  
   ```bash
   git clone https://github.com/KaisarYetiandi/C2Hunter.git
   ```  

2. **Masuk ke Folder Project**  
   ```
   cd C2Hunter
   ```  

3. **Install Dependencies**  
   ```
   pip install -r requirements.txt
   ```  

4. **Jalankan Versi Terminal**  
   ```
   python main.py --ip [TARGET_IP]
   ```  
   *Contoh:*  
   ```
   python main.py --ip 192.168.1.100
   ```  

5. **Jalankan Versi GUI** 
   ```
   python -m gui.main_window
   ```  
   
