import os
import sys
import hashlib
import base64
import requests # Thư viện gọi API (VirusTotal kiểm tra mã độc)

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

class AdvancedSecurityToolkit:
    def __init__(self):
        print("==========================================")
        print("     ADVANCED iOS SECURITY TOOLKIT        ")
        print("==========================================")

    # ==========================================
    # TÍNH NĂNG 1: KIỂM TRA MÃ ĐỘC QUA HASH (SHA-256)
    # ==========================================
    def calculate_file_hash(self, file_path):
        """Tính mã SHA-256 của một tập tin cục bộ"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            print(f"\n[+] Đã tính Hash cho file: {os.path.basename(file_path)}")
            print(f"    - SHA-256: {file_hash}")
            return file_hash
        except FileNotFoundError:
            print(f"    [x] Lỗi: Không tìm thấy file tại đường dẫn: {file_path}")
            return None
        except Exception as e:
            print(f"    [x] Lỗi khi đọc file: {e}")
            return None

    def check_malware_virustotal(self, file_hash, api_key=None):
        """
        Kiểm tra mã hash trên cơ sở dữ liệu công khai của VirusTotal (Yêu cầu API Key miễn phí)
        Nếu không có API key, hệ thống sẽ đối chiếu với danh sách mẫu cục bộ.
        """
        print("\n[+] Đang kiểm tra mã độc qua Hash...")
        
        # 1. Đối chiếu cơ sở dữ liệu mẫu cục bộ (Offline Database)
        local_known_malware_hashes = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # Ví dụ hash file trống
            "cf23df2207d99a74fbe169e3eba035e633b65d9471040e20aed93764f569faa0"
        ]
        
        if file_hash in local_known_malware_hashes:
            print("    [!] CẢNH BÁO: Mã hash khớp với mẫu mã độc trong cơ sở dữ liệu cục bộ!")
            return True
            
        # 2. Kiểm tra qua VirusTotal API (Nếu người dùng có cung cấp key)
        if api_key:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": api_key}
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious_count = stats.get('malicious', 0)
                    print(f"    - Kết quả từ VirusTotal: Phát hiện {malicious_count} công cụ bảo mật đánh giá là độc hại.")
                    if malicious_count > 0:
                        print("    [!] CẢNH BÁO: File này có khả năng là mã độc!")
                        return True
                elif response.status_code == 404:
                    print("    [-] Sạch: Không tìm thấy dữ liệu cảnh báo trên VirusTotal (File có thể là mới hoặc an toàn).")
                else:
                    print(f"    [x] Lỗi kết nối API VirusTotal: Mã phản hồi {response.status_code}")
            except Exception as e:
                print(f"    [x] Không thể kết nối tới máy chủ VirusTotal: {e}")
        else:
            print("    [-] Đã kiểm tra qua cơ sở dữ liệu cục bộ an toàn (Chưa cấu hình API Key VirusTotal).")
        
        return False

    # ==========================================
    # TÍNH NĂNG 2: MÃ HÓA & GIẢI MÃ TẬP TIN (FERNET / AES)
    # ==========================================
    def _generate_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Tạo khóa mã hóa chuẩn từ mật khẩu người dùng"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_file(self, file_path, password):
        """Mã hóa file an toàn bằng mật khẩu"""
        if not HAS_CRYPTOGRAPHY:
            print("    [x] Lỗi: Cần cài đặt thư viện 'cryptography' để chạy tính năng mã hóa.")
            return
            
        print(f"\n[+] Đang tiến hành mã hóa file: {os.path.basename(file_path)}")
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
                
            salt = os.urandom(16)
            key = self._generate_key_from_password(password, salt)
            f = Fernet(key)
            encrypted_data = f.encrypt(file_data)
            
            # Ghi file đã mã hóa (thêm đuôi .enc)
            output_path = file_path + ".enc"
            with open(output_path, "wb") as f:
                f.write(salt + encrypted_data)
                
            print(f"    [✔] Thành công! File mã hóa lưu tại: {output_path}")
            return output_path
        except Exception as e:
            print(f"    [x] Lỗi mã hóa file: {e}")
            return None

    def decrypt_file(self, encrypted_file_path, password):
        """Giải mã file bằng đúng mật khẩu đã dùng khi mã hóa"""
        if not HAS_CRYPTOGRAPHY:
            print("    [x] Lỗi: Cần cài đặt thư viện 'cryptography' để chạy tính năng giải mã.")
            return
            
        print(f"\n[+] Đang tiến hành giải mã file: {os.path.basename(encrypted_file_path)}")
        try:
            with open(encrypted_file_path, "rb") as f:
                data = f.read()
                
            salt = data[:16]
            encrypted_data = data[16:]
            
            key = self._generate_key_from_password(password, salt)
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            
            # Phục hồi tên file gốc (bỏ đuôi .enc)
            output_path = encrypted_file_path[:-4] if encrypted_file_path.endswith(".enc") else encrypted_file_path + ".dec"
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
                
            print(f"    [✔] Thành công! File giải mã lưu tại: {output_path}")
            return output_path
        except Exception as e:
            print(f"    [x] Lỗi giải mã (Sai mật khẩu hoặc file bị hỏng): {e}")
            return None

# ==========================================
# CHẠY THỬ NGHIỆM TRÊN PYTHONISTA/PYTO
# ==========================================
if __name__ == "__main__":
    toolkit = AdvancedSecurityToolkit()
    
    # Tạo một file văn bản mẫu để test trực tiếp
    test_file = "my_secret_notes.txt"
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("Day la tai lieu mat can bao mat cao tren iPhone.")
        
    # 1. Tính hash và kiểm tra mã độc
    file_hash = toolkit.calculate_file_hash(test_file)
    if file_hash:
        toolkit.check_malware_virustotal(file_hash, api_key=None) # Thay bằng API Key thật nếu có
        
    # 2. Mã hóa file với mật khẩu
    secret_password = "MatKhauCucKyAnToan@123"
    encrypted_path = toolkit.encrypt_file(test_file, secret_password)
    
    # 3. Giải mã lại file
    if encrypted_path:
        toolkit.decrypt_file(encrypted_path, secret_password)
